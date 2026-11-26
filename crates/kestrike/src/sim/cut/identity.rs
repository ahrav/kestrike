//! A cut's identity: operation, registered site, occurrence, boundary,
//! failure class and effect mask, with canonical bytes whose order is the
//! cut order.

use std::cmp::Ordering;

use sha2::{Digest, Sha256};

const SEPARATOR: &[u8; 30] = b"image-cache recovery sites v1\0";

/// A registered interruption site in a recovery workload. Each
/// discriminant is the site's code in descriptors, cuts and the registry
/// hash input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum Site {
    Submission = 1,
    MediaEffect = 2,
    Completion = 3,
    Persistence = 4,
    Publication = 5,
    Exclusion = 6,
    Successor = 7,
    Response = 8,
    Reuse = 9,
    RecoveryMutation = 10,
}

impl Site {
    pub(crate) const ALL: [Self; 10] = [
        Self::Submission,
        Self::MediaEffect,
        Self::Completion,
        Self::Persistence,
        Self::Publication,
        Self::Exclusion,
        Self::Successor,
        Self::Response,
        Self::Reuse,
        Self::RecoveryMutation,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Submission => "accepted-submission",
            Self::MediaEffect => "permitted-media-effect",
            Self::Completion => "completion-posting-and-delivery",
            Self::Persistence => "qualified-persistence",
            Self::Publication => "root-or-admission-publication",
            Self::Exclusion => "protected-exclusion",
            Self::Successor => "first-successor-visibility",
            Self::Response => "external-response-observation",
            Self::Reuse => "reuse",
            Self::RecoveryMutation => "recovery-mutation",
        }
    }

    pub(crate) fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|site| *site as u16 == code)
    }
}

pub(crate) fn registry() -> [(u16, &'static str); 10] {
    Site::ALL.map(|site| (site as u16, site.name()))
}

/// SHA-256 of the separator and, for each entry in `entries` order, its
/// big-endian code, name length and name bytes. The length prefix keeps
/// name boundaries distinct in the hash input.
pub(crate) fn registry_hash(entries: &[(u16, &str)]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(SEPARATOR);
    for (code, name) in entries {
        hash.update(code.to_be_bytes());
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
    }
    hash.finalize().into()
}

/// Which side of its site a cut falls on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum Boundary {
    Before = 1,
    After = 2,
}

impl Boundary {
    pub(crate) const ALL: [Self; 2] = [Self::Before, Self::After];
}

/// The failure that interrupts the workload at a cut, a closed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum Class {
    /// The owner process dies while the controller and media stay live.
    ProcessDeath = 1,
    /// The host or the device fails.
    HostOrDevice = 2,
    /// The controller resets.
    ControllerReset = 3,
    /// A replacement controller attaches to the media.
    ReplacementAttach = 4,
}

impl Class {
    pub(crate) const ALL: [Self; 4] = [
        Self::ProcessDeath,
        Self::HostOrDevice,
        Self::ControllerReset,
        Self::ReplacementAttach,
    ];
}

/// One interruption point and its device outcome. `mask` holds one word
/// per child command the boundary holds, in the boundary's order; bit `i`
/// of a word is set when block `i` of that child's range landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cut {
    pub(crate) operation: u16,
    /// A site code; [`plan`](super::plan) refuses one outside the
    /// registry.
    pub(crate) site: u16,
    pub(crate) occurrence: u32,
    pub(crate) boundary: Boundary,
    pub(crate) class: Class,
    pub(crate) mask: Vec<u64>,
}

impl Cut {
    /// Operation, site, occurrence, boundary, class, the mask's word count
    /// and each word, big-endian at fixed widths, so byte order follows the
    /// fields' numeric order.
    pub(crate) fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(18 + 8 * self.mask.len());
        out.extend_from_slice(&self.operation.to_be_bytes());
        out.extend_from_slice(&self.site.to_be_bytes());
        out.extend_from_slice(&self.occurrence.to_be_bytes());
        out.push(self.boundary as u8);
        out.push(self.class as u8);
        out.extend_from_slice(&(self.mask.len() as u64).to_be_bytes());
        for word in &self.mask {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Cuts compare by their canonical bytes, the total order an enumeration
/// follows.
impl Ord for Cut {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical().cmp(&other.canonical())
    }
}

impl PartialOrd for Cut {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
