//! Evidence scoped to one read identity or one publication incarnation.
//! Per-read deadlines and cancellation requests stay attached to the live
//! operation. Publication residency follows its exact allocation and its
//! key's fingerprint, so a reused slot names a distinct obligation.

use crate::storage::{AllocationId, ControlRefusal, ReadOp};

/// The bytes expected for one publication, bound to its allocation. With
/// the key's fingerprint, which `Soak` holds per key, the allocation forms
/// the publication's index identity.
#[derive(Debug, Clone, Copy)]
pub(super) struct Publication {
    pub(super) generation: u32,
    pub(super) len: usize,
    pub(super) allocation: AllocationId,
    pub(super) resident: bool,
}

/// Logical evidence lives until an observed terminal retires this exact read.
/// An overdue verdict leaves its command custody with the volume.
pub(crate) struct Read {
    pub(crate) id: u64,
    pub(super) run: u64,
    pub(super) op: ReadOp,
    pub(super) admitted_at: u64,
    pub(super) deadline: u64,
    pub(super) cancellation: Option<Result<(), ControlRefusal>>,
    pub(super) stalled: bool,
    pub(super) key: u8,
    pub(super) generation: u32,
    pub(super) len: usize,
    pub(super) bytes: Vec<u8>,
}
