//! The cut enumerator against hand-written cut sets for zero, one and two
//! outstanding child commands under both unit declarations, its refusals,
//! the failure-class table, the registry and descriptor hashes, and the
//! canonical bytes two fresh worker processes enumerate alike.

use sha2::{Digest, Sha256};

use super::cut::{
    Boundary, Child, Class, Cut, Descriptor, MaskError, Point, Reach, Refusal, Site, State, Unit,
    enumerate, plan, registry, registry_hash,
};

use Boundary::{After, Before};
use Class::{ControllerReset as Reset, ProcessDeath as Death};

/// The workload's PUT of key 0.
const KEY_0: u16 = 0;
/// The workload's PUT of key 1.
const KEY_1: u16 = 1;

/// A two-block write at the volume's start: two units of 512 bytes, one
/// unit of 16 KiB.
const C0: Child = Child {
    lba: 0,
    blocks: 2,
    state: State::Outstanding,
};

/// A two-block write across the first 16 KiB boundary, which lands block
/// by block under either declaration.
const C1: Child = Child {
    lba: 31,
    blocks: 2,
    state: State::Outstanding,
};

fn point(operation: u16, site: Site, before: &[Child], after: &[Child]) -> Point {
    Point {
        operation,
        site: site as u16,
        occurrence: 0,
        before: before.to_vec(),
        after: after.to_vec(),
    }
}

fn required(site: Site) -> Reach {
    Reach {
        site: site as u16,
        required: true,
    }
}

fn descriptor(unit: Unit, reach: Vec<Reach>, points: Vec<Point>) -> Descriptor {
    Descriptor {
        unit,
        classes: vec![Death, Reset],
        reach,
        points,
        bound: 64,
    }
}

fn cut(operation: u16, site: Site, boundary: Boundary, class: Class, mask: &[u64]) -> Cut {
    Cut {
        operation,
        site: site as u16,
        occurrence: 0,
        boundary,
        class,
        mask: mask.to_vec(),
    }
}

/// Both keys' responses, at which no child command is outstanding.
fn zero(unit: Unit) -> Descriptor {
    descriptor(
        unit,
        vec![required(Site::Response)],
        vec![
            point(KEY_0, Site::Response, &[], &[]),
            point(KEY_1, Site::Response, &[], &[]),
        ],
    )
}

/// Key 0's write submitted, leaving one child outstanding after it, and
/// key 1's response, which the descriptor reaches without requiring it.
fn one(unit: Unit) -> Descriptor {
    descriptor(
        unit,
        vec![
            required(Site::Submission),
            Reach {
                site: Site::Response as u16,
                required: false,
            },
        ],
        vec![
            point(KEY_0, Site::Submission, &[], &[C0]),
            point(KEY_1, Site::Response, &[], &[]),
        ],
    )
}

/// Key 0's write submitted, then key 1's while key 0's is still
/// outstanding, leaving two children outstanding after it.
fn two(unit: Unit) -> Descriptor {
    descriptor(
        unit,
        vec![required(Site::Submission)],
        vec![
            point(KEY_0, Site::Submission, &[], &[C0]),
            point(KEY_1, Site::Submission, &[C0], &[C0, C1]),
        ],
    )
}

fn responses() -> Vec<Cut> {
    let mut cuts = Vec::new();
    for key in [KEY_0, KEY_1] {
        cuts.extend([
            cut(key, Site::Response, Before, Death, &[]),
            cut(key, Site::Response, Before, Reset, &[]),
            cut(key, Site::Response, After, Death, &[]),
            cut(key, Site::Response, After, Reset, &[]),
        ]);
    }
    cuts
}

#[test]
fn zero_outstanding_children_enumerate_one_cut_per_boundary_and_class() {
    for unit in [Unit::Sector, Unit::Kib16] {
        assert_eq!(enumerate(&zero(unit)).unwrap(), responses(), "{unit:?}");
    }
}

/// Process death lands the outstanding write whole; a reset lands any
/// whole units of it: any subset of its two blocks under 512-byte units,
/// both or neither under 16 KiB units.
#[test]
fn one_outstanding_child_enumerates_its_whole_unit_masks() {
    let sub = Site::Submission;
    let mut sector = vec![
        cut(KEY_0, sub, Before, Death, &[]),
        cut(KEY_0, sub, Before, Reset, &[]),
        cut(KEY_0, sub, After, Death, &[0b11]),
        cut(KEY_0, sub, After, Reset, &[0b00]),
        cut(KEY_0, sub, After, Reset, &[0b01]),
        cut(KEY_0, sub, After, Reset, &[0b10]),
        cut(KEY_0, sub, After, Reset, &[0b11]),
    ];
    sector.extend(responses()[4..].iter().cloned());
    assert_eq!(enumerate(&one(Unit::Sector)).unwrap(), sector);
    let mut kib16 = vec![
        cut(KEY_0, sub, Before, Death, &[]),
        cut(KEY_0, sub, Before, Reset, &[]),
        cut(KEY_0, sub, After, Death, &[0b11]),
        cut(KEY_0, sub, After, Reset, &[0b00]),
        cut(KEY_0, sub, After, Reset, &[0b11]),
    ];
    kib16.extend(responses()[4..].iter().cloned());
    assert_eq!(enumerate(&one(Unit::Kib16)).unwrap(), kib16);
}

/// The second write crosses a 16 KiB boundary, so it lands block by block
/// under either declaration, and key 1's after boundary holds every pair
/// of the two children's masks.
#[test]
fn two_outstanding_children_enumerate_every_pair_of_whole_unit_masks() {
    let sub = Site::Submission;
    let sector = [
        cut(KEY_0, sub, Before, Death, &[]),
        cut(KEY_0, sub, Before, Reset, &[]),
        cut(KEY_0, sub, After, Death, &[0b11]),
        cut(KEY_0, sub, After, Reset, &[0b00]),
        cut(KEY_0, sub, After, Reset, &[0b01]),
        cut(KEY_0, sub, After, Reset, &[0b10]),
        cut(KEY_0, sub, After, Reset, &[0b11]),
        cut(KEY_1, sub, Before, Death, &[0b11]),
        cut(KEY_1, sub, Before, Reset, &[0b00]),
        cut(KEY_1, sub, Before, Reset, &[0b01]),
        cut(KEY_1, sub, Before, Reset, &[0b10]),
        cut(KEY_1, sub, Before, Reset, &[0b11]),
        cut(KEY_1, sub, After, Death, &[0b11, 0b11]),
        cut(KEY_1, sub, After, Reset, &[0b00, 0b00]),
        cut(KEY_1, sub, After, Reset, &[0b00, 0b01]),
        cut(KEY_1, sub, After, Reset, &[0b00, 0b10]),
        cut(KEY_1, sub, After, Reset, &[0b00, 0b11]),
        cut(KEY_1, sub, After, Reset, &[0b01, 0b00]),
        cut(KEY_1, sub, After, Reset, &[0b01, 0b01]),
        cut(KEY_1, sub, After, Reset, &[0b01, 0b10]),
        cut(KEY_1, sub, After, Reset, &[0b01, 0b11]),
        cut(KEY_1, sub, After, Reset, &[0b10, 0b00]),
        cut(KEY_1, sub, After, Reset, &[0b10, 0b01]),
        cut(KEY_1, sub, After, Reset, &[0b10, 0b10]),
        cut(KEY_1, sub, After, Reset, &[0b10, 0b11]),
        cut(KEY_1, sub, After, Reset, &[0b11, 0b00]),
        cut(KEY_1, sub, After, Reset, &[0b11, 0b01]),
        cut(KEY_1, sub, After, Reset, &[0b11, 0b10]),
        cut(KEY_1, sub, After, Reset, &[0b11, 0b11]),
    ];
    assert_eq!(enumerate(&two(Unit::Sector)).unwrap(), sector);
    let kib16 = [
        cut(KEY_0, sub, Before, Death, &[]),
        cut(KEY_0, sub, Before, Reset, &[]),
        cut(KEY_0, sub, After, Death, &[0b11]),
        cut(KEY_0, sub, After, Reset, &[0b00]),
        cut(KEY_0, sub, After, Reset, &[0b11]),
        cut(KEY_1, sub, Before, Death, &[0b11]),
        cut(KEY_1, sub, Before, Reset, &[0b00]),
        cut(KEY_1, sub, Before, Reset, &[0b11]),
        cut(KEY_1, sub, After, Death, &[0b11, 0b11]),
        cut(KEY_1, sub, After, Reset, &[0b00, 0b00]),
        cut(KEY_1, sub, After, Reset, &[0b00, 0b01]),
        cut(KEY_1, sub, After, Reset, &[0b00, 0b10]),
        cut(KEY_1, sub, After, Reset, &[0b00, 0b11]),
        cut(KEY_1, sub, After, Reset, &[0b11, 0b00]),
        cut(KEY_1, sub, After, Reset, &[0b11, 0b01]),
        cut(KEY_1, sub, After, Reset, &[0b11, 0b10]),
        cut(KEY_1, sub, After, Reset, &[0b11, 0b11]),
    ];
    assert_eq!(enumerate(&two(Unit::Kib16)).unwrap(), kib16);
}

fn fixtures() -> Vec<Descriptor> {
    [Unit::Sector, Unit::Kib16]
        .into_iter()
        .flat_map(|unit| [zero(unit), one(unit), two(unit)])
        .collect()
}

/// Every enumeration strictly increases in canonical bytes.
#[test]
fn enumerations_follow_one_total_order_of_canonical_bytes() {
    for descriptor in fixtures() {
        let cuts = enumerate(&descriptor).unwrap();
        for pair in cuts.windows(2) {
            assert!(pair[0].canonical() < pair[1].canonical(), "{pair:?}");
            assert!(pair[0] < pair[1]);
        }
    }
}

/// SHA-256 over the registry hash, then each fixture's descriptor hash
/// and its cut table, each cut's canonical bytes behind their length, in
/// fixture and canonical order.
pub(crate) const PINNED: &str = "f3610b17728c24917d57d6872c257d5b6d388f023256454f8e0b20203ddaa49c";

/// This process's digest of the registry, the fixture descriptors and
/// their cut tables, when it equals the pinned one.
///
/// # Errors
///
/// A refused fixture, or the digest against the pinned one.
pub(crate) fn pinned_cuts() -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(registry_hash(&registry()));
    for descriptor in fixtures() {
        hash.update(descriptor.hash());
        for cut in enumerate(&descriptor).map_err(|refusal| format!("{refusal:?}"))? {
            let bytes = cut.canonical();
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
    }
    let digest: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if digest != PINNED {
        return Err(format!("cuts {digest}, pinned {PINNED}"));
    }
    Ok(digest)
}

#[test]
fn the_library_process_enumerates_the_pinned_cut_tables() {
    pinned_cuts().unwrap();
}

/// One completed, one qualified and one outstanding single-block write
/// after key 0's completion, under every class.
fn mixed() -> Descriptor {
    let completed = Child {
        lba: 0,
        blocks: 1,
        state: State::Completed,
    };
    let qualified = Child {
        lba: 1,
        state: State::Qualified,
        ..completed
    };
    let outstanding = Child {
        lba: 2,
        state: State::Outstanding,
        ..completed
    };
    let mut descriptor = descriptor(
        Unit::Sector,
        vec![required(Site::Completion)],
        vec![point(
            KEY_0,
            Site::Completion,
            &[],
            &[completed, qualified, outstanding],
        )],
    );
    descriptor.classes = Class::ALL.to_vec();
    descriptor
}

/// Only a host or device failure may drop a completed write, only process
/// death requires the outstanding one whole, and no class drops the
/// qualified one.
#[test]
fn the_failure_class_decides_which_children_land_whole() {
    let descriptor = mixed();
    let cuts = enumerate(&descriptor).unwrap();
    let after = |class| -> Vec<Vec<u64>> {
        cuts.iter()
            .filter(|cut| cut.boundary == After && cut.class == class)
            .map(|cut| cut.mask.clone())
            .collect()
    };
    assert_eq!(after(Death), [[1, 1, 1]]);
    assert_eq!(after(Reset), [[1, 1, 0], [1, 1, 1]]);
    assert_eq!(after(Class::ReplacementAttach), [[1, 1, 0], [1, 1, 1]]);
    assert_eq!(
        after(Class::HostOrDevice),
        [[0, 1, 0], [0, 1, 1], [1, 1, 0], [1, 1, 1]]
    );
}

/// Required cuts are the cuts at the sites the descriptor requires, and a
/// plan may omit them.
#[test]
fn required_cuts_are_the_cuts_of_required_reached_sites() {
    let descriptor = one(Unit::Sector);
    let cuts = enumerate(&descriptor).unwrap();
    let required: Vec<&Cut> = cuts
        .iter()
        .filter(|cut| descriptor.requires(cut.site))
        .collect();
    assert_eq!(required.len(), 7);
    assert!(
        required
            .iter()
            .all(|cut| cut.site == Site::Submission as u16)
    );
    assert!(!descriptor.requires(Site::Response as u16));
    let planned = plan(&descriptor, &cuts[7..]).unwrap();
    assert_eq!(planned, cuts[7..]);
}

/// A plan lists cuts in canonical order whatever order it was given in.
#[test]
fn a_plan_of_legal_cuts_is_admitted_in_canonical_order() {
    let descriptor = two(Unit::Kib16);
    let cuts = enumerate(&descriptor).unwrap();
    let reversed: Vec<Cut> = cuts.iter().rev().cloned().collect();
    assert_eq!(plan(&descriptor, &reversed).unwrap(), cuts);
}

#[test]
fn plan_admits_exactly_the_enumerated_cuts() {
    for mut descriptor in fixtures().into_iter().chain([mixed()]) {
        descriptor.classes = Class::ALL.to_vec();
        descriptor.bound = 1024;
        let cuts = enumerate(&descriptor).unwrap();
        for point in &descriptor.points {
            for boundary in Boundary::ALL {
                for class in Class::ALL {
                    for words in 0..=3 {
                        for code in 0..8u64.pow(words) {
                            let mask = (0..words).map(|at| code >> (3 * at) & 0b111).collect();
                            let candidate = Cut {
                                operation: point.operation,
                                site: point.site,
                                occurrence: point.occurrence,
                                boundary,
                                class,
                                mask,
                            };
                            assert_eq!(
                                plan(&descriptor, std::slice::from_ref(&candidate)).is_ok(),
                                cuts.contains(&candidate),
                                "{candidate:?}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn a_site_outside_the_registry_refuses() {
    let mut descriptor = zero(Unit::Sector);
    descriptor.reach.push(Reach {
        site: 11,
        required: false,
    });
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::Unregistered { site: 11 })
    );
    let mut descriptor = zero(Unit::Sector);
    descriptor.points[1].site = 11;
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::Unregistered { site: 11 })
    );
    let mut stale = cut(KEY_0, Site::Response, Before, Death, &[]);
    stale.site = 0;
    assert_eq!(
        plan(&zero(Unit::Sector), &[stale]),
        Err(Refusal::Unregistered { site: 0 })
    );
}

#[test]
fn a_point_at_an_unreached_site_refuses() {
    let mut descriptor = zero(Unit::Sector);
    descriptor.points[0].site = Site::Completion as u16;
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::Unreached {
            site: Site::Completion as u16
        })
    );
}

#[test]
fn a_repeated_point_reach_entry_or_planned_cut_refuses() {
    let mut descriptor = zero(Unit::Sector);
    descriptor.points[1].operation = KEY_0;
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::DuplicatePoint {
            operation: KEY_0,
            site: Site::Response as u16,
            occurrence: 0
        })
    );
    descriptor.points[1].occurrence = 1;
    assert_eq!(enumerate(&descriptor).unwrap().len(), 8);
    let mut descriptor = zero(Unit::Sector);
    descriptor.reach.push(Reach {
        site: Site::Response as u16,
        required: false,
    });
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::DuplicateReach {
            site: Site::Response as u16
        })
    );
    let once = cut(KEY_1, Site::Response, After, Reset, &[]);
    assert_eq!(
        plan(&zero(Unit::Sector), &[once.clone(), once.clone()]),
        Err(Refusal::DuplicateCut(once))
    );
}

#[test]
fn a_planned_cut_at_no_point_or_class_of_the_descriptor_refuses() {
    let descriptor = zero(Unit::Sector);
    for absent in [
        cut(2, Site::Response, Before, Death, &[]),
        cut(KEY_0, Site::Response, Before, Class::HostOrDevice, &[]),
    ] {
        assert_eq!(
            plan(&descriptor, std::slice::from_ref(&absent)),
            Err(Refusal::Absent(absent))
        );
    }
}

/// Under 16 KiB units the first write lands whole or not at all, so
/// landing its first block is half a unit; under 512-byte units it is one
/// whole unit.
#[test]
fn a_half_unit_mask_refuses_under_the_larger_unit() {
    let half = cut(KEY_0, Site::Submission, After, Reset, &[0b01]);
    assert_eq!(
        plan(&two(Unit::Kib16), std::slice::from_ref(&half)),
        Err(Refusal::Mask {
            cut: half.clone(),
            error: MaskError::HalfUnit { child: 0 }
        })
    );
    assert_eq!(
        plan(&two(Unit::Sector), std::slice::from_ref(&half)).unwrap(),
        [half]
    );
}

#[test]
fn a_mask_outside_the_childs_range_refuses() {
    let descriptor = two(Unit::Sector);
    let past = cut(KEY_0, Site::Submission, After, Reset, &[0b100]);
    assert_eq!(
        plan(&descriptor, std::slice::from_ref(&past)),
        Err(Refusal::Mask {
            cut: past,
            error: MaskError::OutsideRange { child: 0 }
        })
    );
}

#[test]
fn a_mask_with_another_word_count_than_its_children_refuses() {
    let descriptor = two(Unit::Sector);
    let extra = cut(KEY_0, Site::Submission, After, Reset, &[0b11, 0b01]);
    let short = cut(KEY_1, Site::Submission, After, Reset, &[0b00]);
    for (cut, children, words) in [(extra, 1, 2), (short, 2, 1)] {
        assert_eq!(
            plan(&descriptor, std::slice::from_ref(&cut)),
            Err(Refusal::Mask {
                cut,
                error: MaskError::Words { children, words }
            })
        );
    }
}

/// A process death drops no outstanding write, and no class drops a
/// qualified completed one; a host or device failure may drop a completed
/// write that lacks qualified persistence.
#[test]
fn a_mask_dropping_a_write_its_class_keeps_refuses() {
    let lost = cut(KEY_0, Site::Submission, After, Death, &[0b01]);
    assert_eq!(
        plan(&two(Unit::Sector), std::slice::from_ref(&lost)),
        Err(Refusal::Mask {
            cut: lost,
            error: MaskError::Dropped { child: 0 }
        })
    );
    let written = |state| Child {
        lba: 0,
        blocks: 1,
        state,
    };
    let mut descriptor = descriptor(
        Unit::Sector,
        vec![required(Site::Persistence)],
        vec![point(
            KEY_0,
            Site::Persistence,
            &[written(State::Completed)],
            &[written(State::Qualified)],
        )],
    );
    descriptor.classes = vec![Class::HostOrDevice];
    let host = |boundary| {
        cut(
            KEY_0,
            Site::Persistence,
            boundary,
            Class::HostOrDevice,
            &[0],
        )
    };
    assert_eq!(
        plan(&descriptor, &[host(After)]),
        Err(Refusal::Mask {
            cut: host(After),
            error: MaskError::Dropped { child: 0 }
        })
    );
    assert_eq!(plan(&descriptor, &[host(Before)]).unwrap(), [host(Before)]);
}

#[test]
fn a_descriptor_past_its_bound_refuses_before_building_a_cut() {
    let mut descriptor = two(Unit::Sector);
    descriptor.bound = 28;
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::Exceeded {
            count: 29,
            bound: 28
        })
    );
    descriptor.bound = 29;
    assert_eq!(enumerate(&descriptor).unwrap().len(), 29);
    let wide = Child { blocks: 64, ..C0 };
    let mut descriptor = descriptor.clone();
    descriptor.points[1].after = [0, 64, 128].map(|lba| Child { lba, ..wide }).to_vec();
    descriptor.bound = u32::MAX;
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::Exceeded {
            count: u128::MAX,
            bound: u32::MAX
        })
    );
}

/// A child's mask word holds one bit per block, so a child of no blocks,
/// of more than 64, or whose range end overflows its address refuses.
#[test]
fn a_child_wider_than_a_mask_word_or_empty_refuses() {
    for blocks in [0, 65] {
        let mut descriptor = two(Unit::Sector);
        descriptor.points[1].before[0].lba = 31;
        descriptor.points[1].before[0].blocks = blocks;
        assert_eq!(
            enumerate(&descriptor),
            Err(Refusal::Range { lba: 31, blocks })
        );
    }
    let mut descriptor = two(Unit::Sector);
    descriptor.points[1].before[0].lba = u64::MAX;
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::Range {
            lba: u64::MAX,
            blocks: 2
        })
    );
}

/// A per-child mask cannot name which of two overlapping writes landed
/// last, so overlapping children at one boundary refuse.
#[test]
fn overlapping_children_at_one_boundary_refuse() {
    let mut descriptor = two(Unit::Sector);
    descriptor.points[1].after[1].lba = 1;
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::Overlap {
            operation: KEY_1,
            site: Site::Submission as u16,
            occurrence: 0
        })
    );
    descriptor.points[1].after[1].lba = 2;
    assert!(enumerate(&descriptor).is_ok());
}

/// A write inside one 16 KiB window lands whole or not at all, however
/// long; a write crossing a window boundary, or spanning two windows,
/// lands block by block.
#[test]
fn a_write_crossing_a_unit_window_lands_block_by_block() {
    let after = |lba, blocks| {
        let child = Child {
            lba,
            blocks,
            state: State::Outstanding,
        };
        let mut descriptor = descriptor(
            Unit::Kib16,
            vec![required(Site::Submission)],
            vec![point(KEY_0, Site::Submission, &[], &[child])],
        );
        descriptor.classes = vec![Reset];
        descriptor.bound = 1 << 20;
        let masks: Vec<u64> = enumerate(&descriptor)
            .unwrap()
            .into_iter()
            .filter(|cut| cut.boundary == After)
            .map(|cut| cut.mask[0])
            .collect();
        masks
    };
    assert_eq!(after(0, 32), [0, u64::from(u32::MAX)]);
    assert_eq!(after(4, 4), [0, 0b1111]);
    assert_eq!(after(30, 4), (0..16).collect::<Vec<u64>>());
    assert_eq!(after(32, 16).len(), 2);
    assert_eq!(after(16, 17).len(), 1 << 17);
}

/// Under 16 KiB units and a host or device failure, a completed write
/// inside one window lands whole or not at all and a qualified write
/// crossing a window lands whole: the after boundary holds exactly two
/// masks, and a half-landed completed write or a torn qualified one
/// refuses.
#[test]
fn completed_and_qualified_writes_keep_their_units_under_16_kib() {
    let completed = Child {
        lba: 0,
        blocks: 2,
        state: State::Completed,
    };
    let qualified = Child {
        lba: 31,
        blocks: 2,
        state: State::Qualified,
    };
    let mut descriptor = descriptor(
        Unit::Kib16,
        vec![required(Site::Persistence)],
        vec![point(
            KEY_0,
            Site::Persistence,
            &[],
            &[completed, qualified],
        )],
    );
    descriptor.classes = vec![Class::HostOrDevice];
    let host = |mask: &[u64]| cut(KEY_0, Site::Persistence, After, Class::HostOrDevice, mask);
    let after: Vec<Cut> = enumerate(&descriptor)
        .unwrap()
        .into_iter()
        .filter(|cut| cut.boundary == After)
        .collect();
    assert_eq!(after, [host(&[0b00, 0b11]), host(&[0b11, 0b11])]);
    for (mask, error) in [
        ([0b01, 0b11], MaskError::HalfUnit { child: 0 }),
        ([0b11, 0b01], MaskError::Dropped { child: 1 }),
    ] {
        assert_eq!(
            plan(&descriptor, &[host(&mask)]),
            Err(Refusal::Mask {
                cut: host(&mask),
                error
            })
        );
    }
}

#[test]
fn a_repeated_failure_class_refuses() {
    let mut descriptor = zero(Unit::Sector);
    descriptor.classes.push(Reset);
    assert_eq!(enumerate(&descriptor), Err(Refusal::DuplicateClass(Reset)));
}

/// A required site with no point, or a descriptor with no class, would
/// enumerate no cut a campaign requires and refuses before any run.
#[test]
fn a_required_reached_site_without_cuts_refuses() {
    let mut descriptor = zero(Unit::Sector);
    descriptor.reach.push(required(Site::Exclusion));
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::NoCuts {
            site: Site::Exclusion as u16
        })
    );
    let mut descriptor = zero(Unit::Sector);
    descriptor.classes.clear();
    assert_eq!(
        enumerate(&descriptor),
        Err(Refusal::NoCuts {
            site: Site::Response as u16
        })
    );
}

/// The registry names ten distinct codes, and its hash changes when a site
/// is added, removed, renamed or moved.
#[test]
fn the_registry_hash_covers_every_site() {
    let sites = registry();
    let codes: Vec<u16> = sites.iter().map(|(code, _)| *code).collect();
    assert_eq!(codes, (1..=10).collect::<Vec<u16>>());
    for (code, _) in sites {
        assert_eq!(Site::from_code(code).map(|site| site as u16), Some(code));
    }
    assert_eq!(Site::from_code(0), None);
    assert_eq!(Site::from_code(11), None);
    let pinned = registry_hash(&sites);
    for at in 0..sites.len() {
        let mut removed = sites.to_vec();
        removed.remove(at);
        assert_ne!(registry_hash(&removed), pinned, "removing {at}");
        let mut renamed = sites.to_vec();
        renamed[at].1 = "renamed";
        assert_ne!(registry_hash(&renamed), pinned, "renaming {at}");
    }
    let mut added = sites.to_vec();
    added.push((11, "crash-during-scan"));
    assert_ne!(registry_hash(&added), pinned);
    let mut moved = sites.to_vec();
    moved.swap(0, 1);
    assert_ne!(registry_hash(&moved), pinned);
}

/// The descriptor hash covers the unit, the bound, the classes,
/// reachability, each point's identity and every child's range, state and
/// position at both boundaries, and stays equal under any declaration
/// order of reach entries, points or classes.
#[test]
fn the_descriptor_hash_covers_reachability_and_units() {
    let base = two(Unit::Sector);
    let pinned = base.hash();
    let edited = |edit: fn(&mut Descriptor)| {
        let mut descriptor = base.clone();
        edit(&mut descriptor);
        descriptor
    };
    let edits = [
        two(Unit::Kib16),
        edited(|d| d.reach[0].required = false),
        edited(|d| d.reach.push(required(Site::Reuse))),
        edited(|d| d.bound += 1),
        edited(|d| {
            d.classes.pop();
        }),
        edited(|d| d.points[0].operation = 2),
        edited(|d| d.points[0].site = Site::Response as u16),
        edited(|d| d.points[1].occurrence = 1),
        edited(|d| d.points[1].before[0].lba = 1),
        edited(|d| d.points[1].before[0].blocks = 3),
        edited(|d| d.points[1].before[0].state = State::Completed),
        edited(|d| d.points[1].before.clear()),
        edited(|d| d.points[1].after[1].state = State::Qualified),
        edited(|d| d.points[1].after.swap(0, 1)),
    ];
    for (at, edit) in edits.iter().enumerate() {
        assert_ne!(edit.hash(), pinned, "edit {at}");
    }
    let mut permuted = base.clone();
    permuted.reach.push(Reach {
        site: Site::Response as u16,
        required: false,
    });
    let pinned = permuted.hash();
    permuted.reach.reverse();
    permuted.points.reverse();
    permuted.classes.reverse();
    assert_eq!(permuted.hash(), pinned);
}
