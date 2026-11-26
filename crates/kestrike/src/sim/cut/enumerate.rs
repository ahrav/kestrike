//! The enumerator: a descriptor's legal cuts in their total order, and the
//! admission of a planned cut set, each refused before any run when the
//! descriptor or a cut names a stale or unreached site, repeats an
//! identity, declares a child range a mask word cannot hold or two
//! overlapping children at one boundary, leaves a required site without
//! cuts, names no point or class of the descriptor, holds an impossible
//! mask or passes a declared bound.
//!
//! A legal mask lands, for every child command its boundary holds, whole
//! atomic units inside the command's range, as the failure class permits
//! for the command's state:
//!
//! | State       | ProcessDeath | ControllerReset, ReplacementAttach | HostOrDevice |
//! |-------------|--------------|------------------------------------|--------------|
//! | Outstanding | whole        | any whole units                    | any whole units |
//! | Completed   | whole        | whole                              | any whole units |
//! | Qualified   | whole        | whole                              | whole        |
//!
//! Process death leaves the controller live, so every command it held
//! still lands whole; a reset or a replacement attach keeps every byte a
//! completion reported; a host or device failure can lose a completed
//! write unless qualified persistence evidence covers it. A child inside
//! one aligned window of the descriptor's unit is one atomic unit; a child
//! crossing a window boundary lands block by block, since atomicity covers
//! only a write inside one window.

use std::collections::BTreeSet;

use super::descriptor::{Child, Descriptor, Point, State, Unit};
use super::identity::{Boundary, Class, Cut, Site};

/// The most blocks a child command spans: one bit of its mask word each.
const MAX_BLOCKS: u8 = 64;

/// Why a cut's mask is impossible, naming the child by its position at
/// the cut's boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaskError {
    /// The mask lands part of a unit.
    HalfUnit { child: usize },
    /// The mask lands a block outside the child's range.
    OutsideRange { child: usize },
    /// The mask's word count differs from the boundary's child count; each
    /// child requires one mask word.
    Words { children: usize, words: usize },
    /// The mask drops a block of a child the class requires whole.
    Dropped { child: usize },
}

/// Why a descriptor or a planned cut set cannot run. Each refusal comes
/// before any cut is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A site code outside the registry.
    Unregistered { site: u16 },
    /// A point at a site the descriptor does not reach.
    Unreached { site: u16 },
    /// Two points with one operation, site and occurrence.
    DuplicatePoint {
        operation: u16,
        site: u16,
        occurrence: u32,
    },
    /// Two reach entries for one site.
    DuplicateReach { site: u16 },
    /// A failure class listed twice.
    DuplicateClass(Class),
    /// A child command spanning zero blocks, more blocks than a mask word
    /// holds, or a range whose end overflows a `u64` address.
    Range { lba: u64, blocks: u8 },
    /// Two children one boundary holds whose ranges share a block.
    Overlap {
        operation: u16,
        site: u16,
        occurrence: u32,
    },
    /// A planned cut listed twice.
    DuplicateCut(Cut),
    /// A planned cut outside the descriptor's points or declared classes.
    Absent(Cut),
    /// A planned cut whose mask no failure of its class produces.
    Mask { cut: Cut, error: MaskError },
    /// The descriptor would enumerate `count` cuts, more than its `bound`.
    Exceeded { count: u128, bound: u32 },
    /// A required site the descriptor reaches that enumerates no cut.
    NoCuts { site: u16 },
}

/// Every legal cut of `descriptor`, in canonical order.
///
/// # Errors
///
/// The descriptor's first [`Refusal`]: a stale site, a point at an
/// unreached site, a repeated point, reach entry or class, a child of no
/// blocks, of more blocks than a mask word holds or whose range end
/// overflows its address, two children at one boundary sharing a block, a
/// required reached site with no cut, or more cuts than the descriptor's
/// bound, counted before any cut is built.
pub(crate) fn enumerate(descriptor: &Descriptor) -> Result<Vec<Cut>, Refusal> {
    let classes = admit(descriptor)?;
    let mut cuts = Vec::new();
    for point in &descriptor.points {
        for boundary in Boundary::ALL {
            for &class in &classes {
                let mut masks = vec![Vec::new()];
                for child in point.children(boundary) {
                    let words = words(*child, class, descriptor.unit);
                    masks = masks
                        .into_iter()
                        .flat_map(|mask: Vec<u64>| {
                            words.iter().map(move |&word| {
                                let mut mask = mask.clone();
                                mask.push(word);
                                mask
                            })
                        })
                        .collect();
                }
                cuts.extend(masks.into_iter().map(|mask| Cut {
                    operation: point.operation,
                    site: point.site,
                    occurrence: point.occurrence,
                    boundary,
                    class,
                    mask,
                }));
            }
        }
    }
    cuts.sort_by_cached_key(Cut::canonical);
    Ok(cuts)
}

/// `cuts` as a planned set of `descriptor`'s cuts, in canonical order.
/// A plan may omit cuts, required ones included; every cut it admits is
/// one [`enumerate`] yields, which `plan` checks by membership after
/// naming any specific mask error.
///
/// # Errors
///
/// The descriptor's refusal as [`enumerate`] reports it, then the first
/// cut naming a stale site, no point or class of the descriptor or an
/// impossible mask, or one listed twice.
pub(crate) fn plan(descriptor: &Descriptor, cuts: &[Cut]) -> Result<Vec<Cut>, Refusal> {
    let enumerated = enumerate(descriptor)?;
    let mut planned = BTreeSet::new();
    for cut in cuts {
        if Site::from_code(cut.site).is_none() {
            return Err(Refusal::Unregistered { site: cut.site });
        }
        let point = descriptor
            .points
            .iter()
            .find(|point| point.identity() == (cut.operation, cut.site, cut.occurrence));
        let Some(point) = point.filter(|_| descriptor.classes.contains(&cut.class)) else {
            return Err(Refusal::Absent(cut.clone()));
        };
        if let Err(error) = legal(point, cut, descriptor.unit) {
            return Err(Refusal::Mask {
                cut: cut.clone(),
                error,
            });
        }
        if enumerated.binary_search(cut).is_err() {
            return Err(Refusal::Absent(cut.clone()));
        }
        if !planned.insert(cut.clone()) {
            return Err(Refusal::DuplicateCut(cut.clone()));
        }
    }
    Ok(planned.into_iter().collect())
}

/// The descriptor's classes in class order, once it passes [`check`], has
/// a cut at every required site and enumerates within its bound; the
/// count runs before any cut is built.
fn admit(descriptor: &Descriptor) -> Result<Vec<Class>, Refusal> {
    check(descriptor)?;
    let classes: Vec<Class> = Class::ALL
        .into_iter()
        .filter(|class| descriptor.classes.contains(class))
        .collect();
    for reach in descriptor.reach.iter().filter(|reach| reach.required) {
        let reached = descriptor
            .points
            .iter()
            .any(|point| point.site == reach.site);
        if classes.is_empty() || !reached {
            return Err(Refusal::NoCuts { site: reach.site });
        }
    }
    let mut count: u128 = 0;
    for point in &descriptor.points {
        for boundary in Boundary::ALL {
            for &class in &classes {
                let masks = point
                    .children(boundary)
                    .iter()
                    .map(|child| 1u128 << landings(*child, class, descriptor.unit))
                    .try_fold(1u128, u128::checked_mul)
                    .unwrap_or(u128::MAX);
                count = count.saturating_add(masks);
            }
        }
    }
    if count > u128::from(descriptor.bound) {
        return Err(Refusal::Exceeded {
            count,
            bound: descriptor.bound,
        });
    }
    Ok(classes)
}

/// Refuses a stale or repeated reach entry, a repeated class, and a point
/// with a stale, unreached or repeated identity, a child range a mask word
/// cannot hold, or two children at one boundary sharing a block.
fn check(descriptor: &Descriptor) -> Result<(), Refusal> {
    let mut reached = BTreeSet::new();
    for reach in &descriptor.reach {
        if Site::from_code(reach.site).is_none() {
            return Err(Refusal::Unregistered { site: reach.site });
        }
        if !reached.insert(reach.site) {
            return Err(Refusal::DuplicateReach { site: reach.site });
        }
    }
    let mut classes = BTreeSet::new();
    if let Some(class) = descriptor
        .classes
        .iter()
        .find(|class| !classes.insert(**class))
    {
        return Err(Refusal::DuplicateClass(*class));
    }
    let mut points = BTreeSet::new();
    for point in &descriptor.points {
        if Site::from_code(point.site).is_none() {
            return Err(Refusal::Unregistered { site: point.site });
        }
        if !reached.contains(&point.site) {
            return Err(Refusal::Unreached { site: point.site });
        }
        if !points.insert(point.identity()) {
            return Err(Refusal::DuplicatePoint {
                operation: point.operation,
                site: point.site,
                occurrence: point.occurrence,
            });
        }
        for child in point.before.iter().chain(&point.after) {
            let fits = child.lba.checked_add(u64::from(child.blocks)).is_some();
            if child.blocks == 0 || child.blocks > MAX_BLOCKS || !fits {
                return Err(Refusal::Range {
                    lba: child.lba,
                    blocks: child.blocks,
                });
            }
        }
        for children in [&point.before, &point.after] {
            let overlaps = children.iter().enumerate().any(|(at, child)| {
                children[at + 1..].iter().any(|other| {
                    child.lba < other.lba + u64::from(other.blocks)
                        && other.lba < child.lba + u64::from(child.blocks)
                })
            });
            if overlaps {
                return Err(Refusal::Overlap {
                    operation: point.operation,
                    site: point.site,
                    occurrence: point.occurrence,
                });
            }
        }
    }
    Ok(())
}

/// Whether `class` requires a child in `state` to land whole.
fn whole(class: Class, state: State) -> bool {
    match state {
        State::Outstanding => class == Class::ProcessDeath,
        State::Completed => class != Class::HostOrDevice,
        State::Qualified => true,
    }
}

/// The word with a bit for each of the child's blocks.
fn range(child: Child) -> u64 {
    u64::MAX >> (64 - u32::from(child.blocks))
}

/// The child's units as words of its mask. A child inside one aligned
/// window of the unit is one atomic unit over its whole range; each block
/// is an independent unit when the child crosses an aligned window
/// boundary.
fn units(child: Child, unit: Unit) -> Vec<u64> {
    let last = child.lba + u64::from(child.blocks) - 1;
    if child.lba / unit.blocks() == last / unit.blocks() {
        return vec![range(child)];
    }
    (0..child.blocks).map(|block| 1 << block).collect()
}

/// How many units of the child land independently under `class`: none
/// when the class requires it whole.
fn landings(child: Child, class: Class, unit: Unit) -> usize {
    if whole(class, child.state) {
        0
    } else {
        units(child, unit).len()
    }
}

/// Every mask word `class` permits the child, in increasing order.
fn words(child: Child, class: Class, unit: Unit) -> Vec<u64> {
    if whole(class, child.state) {
        return vec![range(child)];
    }
    let units = units(child, unit);
    let mut words: Vec<u64> = (0..1u128 << units.len())
        .map(|subset| {
            units
                .iter()
                .enumerate()
                .filter(|(at, _)| subset >> at & 1 == 1)
                .fold(0, |word, (_, unit)| word | unit)
        })
        .collect();
    words.sort_unstable();
    words
}

/// Whether `cut`'s mask is one its class permits at `point`.
fn legal(point: &Point, cut: &Cut, unit: Unit) -> Result<(), MaskError> {
    let children = point.children(cut.boundary);
    if cut.mask.len() != children.len() {
        return Err(MaskError::Words {
            children: children.len(),
            words: cut.mask.len(),
        });
    }
    for (child, (&command, &landed)) in children.iter().zip(&cut.mask).enumerate() {
        if landed & !range(command) != 0 {
            return Err(MaskError::OutsideRange { child });
        }
        if units(command, unit)
            .iter()
            .any(|&part| landed & part != 0 && landed & part != part)
        {
            return Err(MaskError::HalfUnit { child });
        }
        if whole(cut.class, command.state) && landed != range(command) {
            return Err(MaskError::Dropped { child });
        }
    }
    Ok(())
}
