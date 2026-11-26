//! The cut descriptor: the plain data a workload declares its interruption
//! points in, with canonical bytes and their SHA-256.
//!
//! A descriptor declares the atomic unit its child commands land in, the
//! failure classes it enumerates, the sites it reaches and which of them
//! it requires, its points and the most cuts it may enumerate. The
//! canonical bytes sort the reach entries by site and the points by
//! identity, so the declaration order of either changes no byte, and they
//! cover every field, so the hash changes when reachability, the unit or
//! any child changes.

use sha2::{Digest, Sha256};

use super::identity::{Boundary, Class};

/// The domain separator ahead of a descriptor's fields.
const SEPARATOR: &[u8; 30] = b"image-cache cut descriptor v1\0";

/// The atomic unit, in 512-byte blocks: a child command inside one aligned
/// window of this many blocks lands whole or not at all, and a child
/// crossing a window boundary lands block by block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum Unit {
    /// 512-byte units: every block lands on its own.
    Sector = 1,
    /// 16 KiB units.
    Kib16 = 32,
}

impl Unit {
    pub(crate) fn blocks(self) -> u64 {
        self as u64
    }
}

/// What a child command has reached when a cut falls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum State {
    /// Submitted, with no completion posted.
    Outstanding = 1,
    /// Completed, without qualified persistence evidence.
    Completed = 2,
    /// Completed under qualified persistence evidence.
    Qualified = 3,
}

/// A child command a boundary holds: its block range on the media and its
/// state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Child {
    /// The first 512-byte block the command writes.
    pub(crate) lba: u64,
    /// The command's length in 512-byte blocks, one bit of a cut's mask
    /// word per block.
    pub(crate) blocks: u8,
    pub(crate) state: State,
}

/// One occurrence of a site within an operation, with the child commands
/// its before and after boundaries hold, in the order a cut's mask names
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Point {
    pub(crate) operation: u16,
    pub(crate) site: u16,
    pub(crate) occurrence: u32,
    pub(crate) before: Vec<Child>,
    pub(crate) after: Vec<Child>,
}

impl Point {
    /// The child commands `boundary` holds.
    pub(crate) fn children(&self, boundary: Boundary) -> &[Child] {
        match boundary {
            Boundary::Before => &self.before,
            Boundary::After => &self.after,
        }
    }

    /// The point's operation, site and occurrence.
    pub(crate) fn identity(&self) -> (u16, u16, u32) {
        (self.operation, self.site, self.occurrence)
    }
}

/// A site the workload reaches, and whether its cuts are required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reach {
    pub(crate) site: u16,
    pub(crate) required: bool,
}

/// A workload's interruption points and the bounds its enumeration runs
/// under. `reach` lists every site the workload reaches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub(crate) unit: Unit,
    pub(crate) classes: Vec<Class>,
    pub(crate) reach: Vec<Reach>,
    pub(crate) points: Vec<Point>,
    /// The most cuts the descriptor may enumerate.
    pub(crate) bound: u32,
}

impl Descriptor {
    /// Whether the descriptor requires the cuts at `site`.
    pub(crate) fn requires(&self, site: u16) -> bool {
        self.reach
            .iter()
            .any(|reach| reach.site == site && reach.required)
    }

    /// The separator, then the unit, the bound and the class set, the
    /// reach entries by site and the points by identity, each child as
    /// its range and state; integers big-endian, every list behind its
    /// length.
    pub(crate) fn canonical(&self) -> Vec<u8> {
        let mut out = SEPARATOR.to_vec();
        out.extend_from_slice(&(self.unit as u32).to_be_bytes());
        out.extend_from_slice(&self.bound.to_be_bytes());
        let classes = Class::ALL
            .iter()
            .filter(|class| self.classes.contains(class))
            .fold(0u8, |set, class| set | 1 << (*class as u8));
        out.push(classes);
        let mut reach = self.reach.clone();
        reach.sort_by_key(|reach| (reach.site, reach.required));
        out.extend_from_slice(&(reach.len() as u64).to_be_bytes());
        for reach in &reach {
            out.extend_from_slice(&reach.site.to_be_bytes());
            out.push(u8::from(reach.required));
        }
        let mut points: Vec<&Point> = self.points.iter().collect();
        points.sort_by_key(|point| point.identity());
        out.extend_from_slice(&(points.len() as u64).to_be_bytes());
        for point in points {
            out.extend_from_slice(&point.operation.to_be_bytes());
            out.extend_from_slice(&point.site.to_be_bytes());
            out.extend_from_slice(&point.occurrence.to_be_bytes());
            for children in [&point.before, &point.after] {
                out.extend_from_slice(&(children.len() as u64).to_be_bytes());
                for child in children {
                    out.extend_from_slice(&child.lba.to_be_bytes());
                    out.push(child.blocks);
                    out.push(child.state as u8);
                }
            }
        }
        out
    }

    /// SHA-256 of the canonical bytes.
    pub(crate) fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical()).into()
    }
}
