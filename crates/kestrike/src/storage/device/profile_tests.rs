//! Persistence profile derivation and qualification over hand-built Identify
//! pages. Each expected unit, granularity and boundary is computed by hand
//! from the fields the fixture writes, at their NVMe and EBS byte offsets.

use super::geometry::DeviceRange;
use super::identify::{IdentifyMalformed, TransferLimits};
use super::identify_fixture::{EBS, Fields, SECTORS, SERIAL, facts};
use super::profile::{
    AtomicsRefusal, Boundary, DeriveRefusal, PersistenceProfile, ProfileKind, ProfileRefusal,
    UnitSource,
};

fn derive(fields: Fields) -> Result<PersistenceProfile, DeriveRefusal> {
    PersistenceProfile::derive(&facts(fields))
}

fn atomics(refusal: AtomicsRefusal) -> Result<PersistenceProfile, DeriveRefusal> {
    Err(DeriveRefusal::Atomics(refusal))
}

fn range(start: u64, len: u32) -> DeviceRange {
    DeviceRange::new(start, len).unwrap()
}

/// The EBS fixture derives a 16 KiB unit, a 4 KiB
/// granularity and both 32-block boundaries at offset 0, from both sources.
#[test]
fn the_captured_ebs_volume_derives_a_sixteen_kib_unit_at_four_kib_granularity() {
    let profile = derive(EBS).unwrap();
    assert_eq!(profile.kind(), ProfileKind::CompletionWithoutVolatileCache);
    assert_eq!(profile.kind().name(), "completion-without-volatile-cache");
    assert_eq!(
        profile.kind().name(),
        crate::oracle::QUALIFIED_BOUNDARY,
        "the kind names the oracle's qualified boundary"
    );
    assert_eq!((profile.unit(), profile.granularity()), (32, 8));
    assert_eq!(profile.unit() * u64::from(profile.sector_size()), 16_384);
    assert_eq!(profile.unit_source(), UnitSource::Both);
    let boundary = Some(Boundary {
        offset: 0,
        period: 32,
    });
    assert_eq!(profile.standard_boundary(), boundary);
    assert_eq!(profile.vendor_boundary(), boundary);
    assert_eq!(profile.limits(), EBS.limits);
    assert_eq!(profile.identity().serial, SERIAL);
    assert!(!profile.atomicity_mode());
}

/// The eligibility predicate refuses first and in its order, each fixture
/// carrying atomics that would refuse `UnitsDisagree`: a cache-present
/// device refuses `VolatileWriteCache`, a page of another serial refuses
/// `Mismatch`, and a block size exponent outside 9 to 31 refuses
/// `Malformed`.
#[test]
fn derivation_returns_the_eligibility_refusal_before_any_atomics_check() {
    let disagreeing = Fields {
        vendor: Some((15, 7, 15)),
        ..EBS
    };
    assert_eq!(
        derive(Fields {
            vwc: 1,
            ..disagreeing
        }),
        Err(DeriveRefusal::Ineligible(
            ProfileRefusal::VolatileWriteCache
        ))
    );
    let mut other = facts(disagreeing);
    other.identity.serial = "vol0fedcba9876543210".to_owned();
    assert_eq!(
        PersistenceProfile::derive(&other),
        Err(DeriveRefusal::Ineligible(ProfileRefusal::Mismatch))
    );
    let mut malformed = facts(Fields {
        lbads: 8,
        ..disagreeing
    });
    malformed.identity.sector_size = 256;
    assert_eq!(
        PersistenceProfile::derive(&malformed),
        Err(DeriveRefusal::Ineligible(ProfileRefusal::Malformed(
            IdentifyMalformed::SectorSize(8)
        )))
    );
}

/// The standard candidate: AWUPF 0 without NSFEAT bit 1 gives one block;
/// NSFEAT bit 1 with NAWUPF 31 gives 32 blocks, 16 KiB at 512 bytes, with
/// granularity one block and the NABO/NABSPF boundary; NSFEAT bit 1 with
/// NAWUPF 0 falls back to AWUPF.
#[test]
fn the_standard_fields_give_their_unit_and_boundary() {
    let standard = |nsfeat, awupf, nawupf| Fields {
        nsfeat,
        awupf,
        nawupf,
        vendor: None,
        ..EBS
    };
    let one = derive(standard(0, 0, 31)).unwrap();
    assert_eq!((one.unit(), one.granularity()), (1, 1));
    assert_eq!(one.unit_source(), UnitSource::OneBlock);
    let controller = derive(standard(0, 7, 31)).unwrap();
    assert_eq!(
        (controller.unit(), controller.unit_source()),
        (8, UnitSource::Standard)
    );
    let sixteen = derive(standard(0x02, 0, 31)).unwrap();
    assert_eq!((sixteen.unit(), sixteen.granularity()), (32, 1));
    assert_eq!(sixteen.unit_source(), UnitSource::Standard);
    assert_eq!(sixteen.vendor_boundary(), None);
    assert_eq!(
        sixteen.standard_boundary(),
        Some(Boundary {
            offset: 0,
            period: 32
        })
    );
    let fallback = derive(standard(0x02, 7, 0)).unwrap();
    assert_eq!(fallback.unit(), 8);
    let unbounded = derive(Fields {
        nabspf: 0,
        ..standard(0x02, 0, 31)
    })
    .unwrap();
    assert_eq!(unbounded.standard_boundary(), None);
}

/// The vendor candidate: NTWPU 31 and NTWPG 7 under the EBS vendor ID and
/// model give 32 blocks at granularity 8; another vendor ID or model leaves
/// the candidate absent, so the standard fields alone decide.
#[test]
fn the_vendor_fields_count_only_under_the_ebs_vendor_and_model() {
    let vendor_only = Fields { nsfeat: 0, ..EBS };
    let profile = derive(vendor_only).unwrap();
    assert_eq!((profile.unit(), profile.granularity()), (32, 8));
    assert_eq!(profile.unit_source(), UnitSource::Vendor);
    assert_eq!(profile.standard_boundary(), None);
    for other in [
        Fields {
            vid: 0x144d,
            ..vendor_only
        },
        Fields {
            model: "Amazon EC2 NVMe Instance Storage",
            ..vendor_only
        },
    ] {
        let profile = derive(other).unwrap();
        assert_eq!((profile.unit(), profile.granularity()), (1, 1));
        assert_eq!(profile.unit_source(), UnitSource::OneBlock);
    }
    let no_boundary = derive(Fields {
        vendor: Some((31, 7, 0)),
        ..vendor_only
    })
    .unwrap();
    assert_eq!(no_boundary.vendor_boundary(), None);
    let widest = derive(Fields {
        vendor: Some((31, 7, u32::MAX)),
        ..vendor_only
    })
    .unwrap();
    assert_eq!(
        widest.vendor_boundary(),
        Some(Boundary {
            offset: 0,
            period: 1 << 32
        }),
        "NTWPB widens before the zero-based increment"
    );
}

/// Both sources reporting different units refuse; agreeing units take the
/// vendor granularity.
#[test]
fn disagreeing_unit_sources_refuse_and_agreeing_ones_take_the_vendor_granularity() {
    assert_eq!(
        derive(Fields {
            vendor: Some((15, 7, 15)),
            ..EBS
        }),
        atomics(AtomicsRefusal::UnitsDisagree {
            standard: 32,
            vendor: 16
        })
    );
    assert_eq!(derive(EBS).unwrap().granularity(), 8);
    assert_eq!(
        derive(Fields {
            vendor: Some((15, 7, 15)),
            limits: TransferLimits {
                command: 4096,
                ..EBS.limits
            },
            ..EBS
        }),
        atomics(AtomicsRefusal::UnitsDisagree {
            standard: 32,
            vendor: 16
        }),
        "disagreeing units refuse before the command limit"
    );
}

/// A standard boundary offset NABO at or past its period NABSPF + 1
/// refuses before the sector size and command checks.
#[test]
fn a_boundary_offset_past_its_period_refuses() {
    assert_eq!(
        derive(Fields {
            nabo: 32,
            vendor: None,
            limits: TransferLimits {
                command: 4096,
                ..EBS.limits
            },
            ..EBS
        }),
        atomics(AtomicsRefusal::BoundaryOffset {
            offset: 32,
            period: 32
        })
    );
    let last = derive(Fields {
        nawupf: 15,
        nabo: 31,
        vendor: None,
        ..EBS
    })
    .unwrap();
    assert_eq!(
        last.standard_boundary(),
        Some(Boundary {
            offset: 31,
            period: 32
        })
    );
}

/// Inconsistent or unissuable geometry refuses by name: a 24-block unit at
/// granularity 8 is no power-of-two multiple; a 16 KiB unit exceeds an
/// 8 KiB command; an 8 KiB sector does not divide 4 KiB; a 24-block stripe
/// is no power of two; and NABO 8 with NABSPF 31 under a 32-block unit
/// leaves no aligned unit that does not cross a boundary.
#[test]
fn inconsistent_geometry_refuses_by_name() {
    assert_eq!(
        derive(Fields {
            nsfeat: 0,
            vendor: Some((23, 7, 0)),
            limits: TransferLimits {
                boundary: 24,
                ..EBS.limits
            },
            ..EBS
        }),
        atomics(AtomicsRefusal::UnitNotGranularityPower {
            unit: 24,
            granularity: 8
        })
    );
    assert_eq!(
        derive(Fields {
            limits: TransferLimits {
                command: 8192,
                ..EBS.limits
            },
            ..EBS
        }),
        atomics(AtomicsRefusal::UnitExceedsCommand {
            unit_bytes: 16_384,
            command: 8192
        })
    );
    assert_eq!(
        derive(Fields {
            lbads: 13,
            nsfeat: 0,
            vendor: None,
            ..EBS
        }),
        atomics(AtomicsRefusal::SectorSize { sector_size: 8192 })
    );
    assert_eq!(
        derive(Fields {
            limits: TransferLimits {
                boundary: 24,
                ..EBS.limits
            },
            ..EBS
        }),
        atomics(AtomicsRefusal::StripeNotPowerOfTwo { stripe: 24 })
    );
    assert_eq!(
        derive(Fields {
            nabo: 8,
            vendor: None,
            ..EBS
        }),
        atomics(AtomicsRefusal::NoQualifyingRange)
    );
    assert_eq!(
        derive(Fields {
            limits: TransferLimits {
                boundary: 8,
                ..EBS.limits
            },
            ..EBS
        }),
        atomics(AtomicsRefusal::NoQualifyingRange),
        "an 8-block stripe splits every 32-block unit"
    );
}

/// Under U = 32, G = 8 and S = 512: aligned 4, 8 and 16 KiB writes and the
/// first and last whole units below capacity qualify; 12 KiB at 0, 8 KiB at
/// 4 KiB, a 32 KiB write, a unit past capacity, an unaligned range and a
/// 2 KiB write below the granularity fail.
#[test]
fn qualified_ranges_are_aligned_power_of_two_granules_within_one_unit() {
    let profile = derive(EBS).unwrap();
    let capacity = SECTORS * 512;
    for (start, len) in [
        (0, 4096),
        (4096, 4096),
        (0, 8192),
        (8192, 8192),
        (0, 16_384),
        (16_384, 16_384),
        (capacity - 16_384, 16_384),
    ] {
        assert!(profile.qualifies(range(start, len)), "{start} {len}");
    }
    for (start, len) in [
        (0, 12_288),
        (4096, 8192),
        (0, 32_768),
        (8192, 16_384),
        (capacity, 16_384),
        (0, 2048),
    ] {
        assert!(!profile.qualifies(range(start, len)), "{start} {len}");
    }
}

/// A boundary at NABO 8 with period 32 under a 16-block unit: the unit at
/// block 0 crosses block 8 and fails, the unit at block 16 qualifies, the
/// unit at block 32 crosses block 40 and fails, and the unit at block 48
/// qualifies. The 32-block unit with NABO 8 refuses at derivation instead.
#[test]
fn a_range_crossing_an_offset_boundary_fails() {
    let profile = derive(Fields {
        nawupf: 15,
        nabo: 8,
        vendor: None,
        ..EBS
    })
    .unwrap();
    assert_eq!(profile.unit(), 16);
    assert!(!profile.qualifies(range(0, 8192)));
    assert!(profile.qualifies(range(8192, 8192)));
    assert!(!profile.qualifies(range(32 * 512, 8192)));
    assert!(profile.qualifies(range(48 * 512, 8192)));
    assert!(
        profile.qualifies(range(0, 4096)),
        "a range ending on the boundary crosses nothing"
    );
}

/// Under both sources, a standard boundary at NABO 8 still decides: the
/// 16-block unit at block 0 crosses block 8 and fails although the vendor
/// boundary of 32 alone admits it. A standard boundary reported with a
/// one-block standard unit applies under the vendor unit too.
#[test]
fn the_standard_boundary_applies_under_the_vendor_unit() {
    let both = derive(Fields {
        nawupf: 15,
        nabo: 8,
        vendor: Some((15, 7, 31)),
        ..EBS
    })
    .unwrap();
    assert_eq!(both.unit_source(), UnitSource::Both);
    assert!(!both.qualifies(range(0, 8192)));
    assert!(both.qualifies(range(8192, 8192)));
    let one_block_standard = derive(Fields {
        nawupf: 0,
        nabo: 8,
        vendor: Some((15, 7, 31)),
        ..EBS
    })
    .unwrap();
    assert_eq!(one_block_standard.unit_source(), UnitSource::Vendor);
    assert_eq!(
        one_block_standard.standard_boundary(),
        Some(Boundary {
            offset: 8,
            period: 32
        })
    );
    assert!(!one_block_standard.qualifies(range(0, 8192)));
}

/// NABO and NABSPF count only under NSFEAT bit 1.
#[test]
fn the_standard_boundary_counts_only_under_nsfeat_bit_one() {
    let profile = derive(Fields {
        nsfeat: 0,
        nabo: 8,
        ..EBS
    })
    .unwrap();
    assert_eq!(profile.standard_boundary(), None);
    assert!(profile.qualifies(range(0, 16_384)));
}

/// A vendor boundary of 24 blocks under a 16-block vendor unit: the unit at
/// block 0 qualifies, the unit at block 16 crosses block 24 and fails, and
/// the unit at block 48 starts on a boundary and qualifies.
#[test]
fn a_range_crossing_a_vendor_boundary_fails() {
    let profile = derive(Fields {
        nsfeat: 0,
        vendor: Some((15, 7, 23)),
        ..EBS
    })
    .unwrap();
    assert_eq!(profile.unit_source(), UnitSource::Vendor);
    assert!(profile.qualifies(range(0, 8192)));
    assert!(!profile.qualifies(range(16 * 512, 8192)));
    assert!(profile.qualifies(range(48 * 512, 8192)));
}

/// A 64-block stripe under a 48-block unit at granularity 24: the unit at
/// block 0 ends inside the first stripe and qualifies, the unit at block 48
/// crosses block 64 and fails; a 24-block granule at block 24 qualifies, at
/// block 48 it crosses and fails, and at block 72 it qualifies.
#[test]
fn a_range_crossing_the_stripe_fails() {
    let profile = derive(Fields {
        nsfeat: 0,
        vendor: Some((47, 23, 0)),
        limits: TransferLimits {
            boundary: 64,
            ..EBS.limits
        },
        ..EBS
    })
    .unwrap();
    assert_eq!((profile.unit(), profile.granularity()), (48, 24));
    assert!(profile.qualifies(range(0, 24_576)));
    assert!(!profile.qualifies(range(48 * 512, 24_576)));
    assert!(profile.qualifies(range(24 * 512, 12_288)));
    assert!(!profile.qualifies(range(48 * 512, 12_288)));
    assert!(profile.qualifies(range(72 * 512, 12_288)));
    let exact = derive(Fields {
        limits: TransferLimits {
            boundary: 32,
            ..EBS.limits
        },
        ..EBS
    })
    .unwrap();
    assert!(
        exact.qualifies(range(0, 16_384)),
        "a unit ending on the stripe edge fits"
    );
}

/// A 2 KiB write on a 4 KiB-sector device is not whole sectors and fails;
/// a one-sector write qualifies.
#[test]
fn a_partial_sector_write_fails_on_a_four_kib_sector_device() {
    let profile = derive(Fields {
        lbads: 12,
        nsfeat: 0,
        vendor: None,
        ..EBS
    })
    .unwrap();
    assert_eq!(profile.sector_size(), 4096);
    assert!(!profile.qualifies(range(0, 2048)));
    assert!(profile.qualifies(range(4096, 4096)));
}

/// NSFEAT bit 6 is recorded and changes no derivation or qualification result.
#[test]
fn the_atomicity_mode_flag_changes_no_result() {
    let plain = derive(EBS).unwrap();
    let flagged = derive(Fields {
        nsfeat: EBS.nsfeat | 0x40,
        ..EBS
    })
    .unwrap();
    assert!(flagged.atomicity_mode());
    assert_eq!(
        (
            flagged.unit(),
            flagged.granularity(),
            flagged.standard_boundary()
        ),
        (plain.unit(), plain.granularity(), plain.standard_boundary())
    );
    for start in (0..64).map(|k| k * 4096) {
        for len in [4096, 8192, 12_288, 16_384, 32_768] {
            assert_eq!(
                flagged.qualifies(range(start, len)),
                plain.qualifies(range(start, len)),
                "{start} {len}"
            );
        }
    }
}

fn crosses_block(boundary: Boundary, start: u64, len: u64) -> bool {
    let next = if start < boundary.offset {
        boundary.offset
    } else {
        boundary.offset + ((start - boundary.offset) / boundary.period + 1) * boundary.period
    };
    next < start + len
}

fn block_rule(profile: &PersistenceProfile, start: u64, len: u64) -> bool {
    let sector = u64::from(profile.sector_size());
    if !len.is_multiple_of(sector) {
        return false;
    }
    let (start, len) = (start / sector, len / sector);
    let granularity = profile.granularity();
    let shape = len.is_multiple_of(granularity)
        && (len / granularity).is_power_of_two()
        && len <= profile.unit();
    let within = start.is_multiple_of(len) && start + len <= profile.identity().capacity / sector;
    let stripe = u64::from(profile.limits().boundary);
    let stripe = (stripe != 0).then_some(Boundary {
        offset: 0,
        period: stripe,
    });
    shape
        && within
        && ![
            profile.standard_boundary(),
            profile.vendor_boundary(),
            stripe,
        ]
        .into_iter()
        .flatten()
        .any(|boundary| crosses_block(boundary, start, len))
}

#[test]
fn qualifies_agrees_with_the_block_rule_across_granularities_boundaries_and_stripes() {
    let mut derived = 0;
    for lbads in [9u8, 12] {
        for (granularity, shift) in [(1u16, 5u32), (3, 3), (5, 2), (8, 2)] {
            let unit = granularity << shift;
            for (nabo, nabspf) in [(0u16, 0u16), (0, unit - 1), (3, 2 * unit)] {
                for vendor_period in [0u32, 3 * u32::from(unit), 2 * u32::from(unit) + 5] {
                    for stripe in [0u32, 64, 16] {
                        let fields = Fields {
                            nsfeat: 0x02,
                            lbads,
                            nawupf: unit - 1,
                            nabo,
                            nabspf,
                            vendor: Some((
                                unit - 1,
                                granularity - 1,
                                vendor_period.saturating_sub(1),
                            )),
                            limits: TransferLimits {
                                boundary: stripe,
                                ..EBS.limits
                            },
                            ..EBS
                        };
                        let unit_blocks = u64::from(unit);
                        let constraints = [
                            (nabspf != 0).then_some(Boundary {
                                offset: u64::from(nabo),
                                period: u64::from(nabspf) + 1,
                            }),
                            (vendor_period != 0).then_some(Boundary {
                                offset: 0,
                                period: u64::from(vendor_period),
                            }),
                            (stripe != 0).then_some(Boundary {
                                offset: 0,
                                period: u64::from(stripe),
                            }),
                        ];
                        let units = ((SECTORS * 512) >> lbads) / unit_blocks;
                        let sector = 1u64 << lbads;
                        let some_unit_qualifies = (0..units)
                            .map(|k| k * unit_blocks)
                            .filter(|start| (start * sector).is_multiple_of(4096))
                            .take(1 << 16)
                            .any(|start| {
                                !constraints
                                    .into_iter()
                                    .flatten()
                                    .any(|boundary| crosses_block(boundary, start, unit_blocks))
                            });
                        let result = derive(fields);
                        let Ok(profile) = result else {
                            assert!(
                                !some_unit_qualifies,
                                "{nabo} {nabspf} {vendor_period} {stripe}"
                            );
                            assert_eq!(result, atomics(AtomicsRefusal::NoQualifyingRange));
                            continue;
                        };
                        assert!(some_unit_qualifies, "{profile:?}");
                        derived += 1;
                        let sector = u64::from(profile.sector_size());
                        let capacity = profile.identity().capacity;
                        let longest = 2 * profile.unit() * sector;
                        let starts = (0..128).chain((capacity / 4096 - 16)..(capacity / 4096));
                        for start in starts.map(|page| page * 4096) {
                            for len in (512..=longest).step_by(512) {
                                let range = range(start, len as u32);
                                assert_eq!(
                                    profile.qualifies(range),
                                    block_rule(&profile, start, len),
                                    "{start} {len} {profile:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(derived >= 100, "{derived} geometries derived");
}

#[test]
fn derivation_finds_a_qualifying_unit_past_the_first_crossings() {
    let profile = derive(Fields {
        nabo: 8,
        nabspf: 47,
        vendor: None,
        ..EBS
    })
    .unwrap();
    assert_eq!(profile.unit(), 32);
    assert!(!profile.qualifies(range(0, 16_384)));
    assert!(!profile.qualifies(range(32 * 512, 16_384)));
    assert!(profile.qualifies(range(64 * 512, 16_384)));
}

/// The standard boundary splits units whose index is 0 or 1 modulo 3 and
/// the vendor boundary of period 80 splits units whose index is 2 modulo 5,
/// so the first qualifying unit is unit 5, past both repeats and inside
/// their least common multiple of 15.
#[test]
fn derivation_scans_to_the_least_common_multiple_of_the_crossing_cycles() {
    let profile = derive(Fields {
        nabo: 8,
        nabspf: 47,
        vendor: Some((31, 0, 79)),
        ..EBS
    })
    .unwrap();
    assert_eq!(profile.unit(), 32);
    assert!(!profile.qualifies(range(2 * 16_384, 16_384)));
    assert!(profile.qualifies(range(5 * 16_384, 16_384)));
}

/// A 4-block unit and granule of 2048 bytes, with the standard boundary at
/// NABO 1 and period 8. The unit at block 4 qualifies in block terms, but a
/// `DeviceRange` starts on a 4096-byte multiple, and each 2048-byte range
/// there crosses the boundary one block after its start, so derivation
/// returns `NoQualifyingRange`.
#[test]
fn derivation_refuses_when_only_starts_off_the_io_unit_qualify() {
    let boundary = Boundary {
        offset: 1,
        period: 8,
    };
    assert!(!crosses_block(boundary, 4, 4));
    for page in 0..64 {
        assert!(crosses_block(boundary, page * 8, 4), "page {page}");
    }
    assert_eq!(
        derive(Fields {
            nawupf: 3,
            nabo: 1,
            nabspf: 7,
            vendor: Some((3, 3, 0)),
            ..EBS
        }),
        atomics(AtomicsRefusal::NoQualifyingRange)
    );
}
