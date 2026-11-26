//! Strict memory placement: after population, [`verify_chunk`] checks each
//! chunk of a mapping against its bound node mask.
//!
//! Invariants:
//!
//! - Placement configuration is validated against the kernel's topology
//!   (possible nodes, memory-bearing nodes, nodes this task may allocate
//!   from) before any mapping exists. Each rejection is a distinct error.
//! - `MPOL_BIND` restricts allocation to the mask; a preferred-node policy is
//!   never used. A node with no room does not fail population: the page fault
//!   reclaims within the mask and then invokes the OOM killer constrained to
//!   the mask's nodes, which kills the largest eligible task, usually this
//!   process. `check_nodes` rejects a nonexistent, memoryless or disallowed
//!   node.
//! - Verification asks the kernel to check each populated chunk against the
//!   bound mask in one walk, right after that chunk's population so its page
//!   tables and page metadata are still cache-resident. If that check
//!   refuses, each page's node is asked for individually, in page order,
//!   through the single-page query, which waits for a migration of that page
//!   in flight. The first page outside the mask names the defect; a chunk
//!   whose every page answers inside the mask passes. The kernel refuses a
//!   range for a wrong-node page and, from Linux 6.7, for a page whose
//!   migration is in flight (compaction moves fresh pages within their node);
//!   earlier kernels skip a page in flight in the walk. Every kernel skips
//!   a page that is not present when the walk reaches it: one reclaimed
//!   after the residency check is re-faulted under the same bound policy, so
//!   it returns inside the mask without having been observed. A passing walk
//!   therefore proves that no page present during it lay outside the mask,
//!   not that every page was seen. None of these calls migrates anything,
//!   and none is `move_pages`, which default container seccomp profiles deny
//!   outright.
//! - Population evidence (`mincore`) and placement evidence (per-page node)
//!   stay separate. Neither promises that pages stay resident or local: the
//!   kernel may still migrate or swap them, and this crate never re-places.
//!   Automatic NUMA balancing skips mappings with an explicit bind policy, so
//!   it neither re-places these pages toward the CPUs that touch them nor
//!   installs hinting faults on them; compaction and explicit migration calls
//!   still move pages within or across the mask's nodes.

use std::ptr::NonNull;

use super::init::{InitError, InitPhase};
use super::mapping::Region;
use super::os::{OsCode, Platform};

/// Highest node count the mask represents; matches the kernel's usual
/// `MAX_NUMNODES` ceiling.
pub const MAX_NODES: usize = 1024;

const WORDS: usize = MAX_NODES / 64;

/// A fixed-width set of memory nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeMask {
    words: [u64; WORDS],
}

impl NodeMask {
    /// The set of exactly `nodes`, or `None` if any node is `>= MAX_NODES`.
    pub fn from_nodes(nodes: &[usize]) -> Option<Self> {
        let mut mask = Self::default();
        for &node in nodes {
            if !mask.insert(node) {
                return None;
            }
        }
        Some(mask)
    }

    /// Adds `node`; `false` if it does not fit the mask.
    pub fn insert(&mut self, node: usize) -> bool {
        if node >= MAX_NODES {
            return false;
        }
        self.words[node / 64] |= 1 << (node % 64);
        true
    }

    pub fn contains(&self, node: usize) -> bool {
        node < MAX_NODES && self.words[node / 64] & (1 << (node % 64)) != 0
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Nodes in ascending order.
    pub fn nodes(&self) -> impl Iterator<Item = usize> + '_ {
        (0..MAX_NODES).filter(|node| self.contains(*node))
    }

    pub(crate) fn words(&self) -> &[u64; WORDS] {
        &self.words
    }

    pub(crate) fn words_mut(&mut self) -> &mut [u64; WORDS] {
        &mut self.words
    }
}

/// What the kernel reports about memory nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topology {
    /// Nodes that exist.
    pub possible: NodeMask,
    /// Nodes with memory.
    pub has_memory: NodeMask,
    /// Nodes this task may allocate from under its cpuset.
    pub allowed: NodeMask,
}

/// Caller-chosen home node for engine-shared controls; the volume's own
/// mask is [`VolumeConfig::nodes`](super::VolumeConfig::nodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementConfig {
    pub control_home: usize,
}

/// Why a placement is rejected. `region` is `Root` for the control home and
/// `Control` for the volume's mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementError {
    /// The volume's mask names no node.
    EmptyNodeMask,
    /// A node is not a possible node on this kernel.
    NodeDoesNotExist { region: Region, node: usize },
    /// A node exists but has no memory.
    NodeWithoutMemory { region: Region, node: usize },
    /// A node has memory but this task's cpuset does not allow it.
    NodeNotAllowed { region: Region, node: usize },
}

/// A placement that passed [`PlacementConfig::validate`] against a topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedPlacement {
    nodes: NodeMask,
    control_home: NodeMask,
}

impl PlacementConfig {
    /// Checks every node of the control home, then of the volume's `nodes`:
    /// existence, then memory, then cpuset permission.
    ///
    /// # Errors
    ///
    /// The first failing check as a [`PlacementError`].
    pub fn validate(
        &self,
        nodes: &NodeMask,
        topology: &Topology,
    ) -> Result<ValidatedPlacement, PlacementError> {
        let control_home =
            NodeMask::from_nodes(&[self.control_home]).ok_or(PlacementError::NodeDoesNotExist {
                region: Region::Root,
                node: self.control_home,
            })?;
        check_nodes(Region::Root, &control_home, topology)?;
        if nodes.is_empty() {
            return Err(PlacementError::EmptyNodeMask);
        }
        check_nodes(Region::Control, nodes, topology)?;
        Ok(ValidatedPlacement {
            nodes: *nodes,
            control_home,
        })
    }
}

/// Empty masks pass; callers requiring a node must reject them.
///
/// # Errors
///
/// Returns the lowest nonexistent, memoryless, or disallowed node.
pub(crate) fn check_nodes(
    region: Region,
    mask: &NodeMask,
    topology: &Topology,
) -> Result<(), PlacementError> {
    for node in mask.nodes() {
        if !topology.possible.contains(node) {
            return Err(PlacementError::NodeDoesNotExist { region, node });
        }
        if !topology.has_memory.contains(node) {
            return Err(PlacementError::NodeWithoutMemory { region, node });
        }
        if !topology.allowed.contains(node) {
            return Err(PlacementError::NodeNotAllowed { region, node });
        }
    }
    Ok(())
}

impl ValidatedPlacement {
    /// The mask bound to `region`: the control home for the root and the
    /// index, the volume's mask for its control mapping.
    pub(crate) fn nodes(&self, region: Region) -> &NodeMask {
        match region {
            Region::Root | Region::Index => &self.control_home,
            Region::Control => &self.nodes,
            Region::Buffers => unreachable!(
                "storage initialization never places the buffer arena, which binds its own mask"
            ),
        }
    }
}

/// Checks one populated chunk of `region` against `nodes`: the kernel's range
/// check first, then, only if it refuses, one node query per page in page
/// order. The first defective page is reported at `first_page` plus its index
/// within the chunk, and no page after it is queried.
///
/// # Safety
///
/// `start..start + len` is a populated, page-aligned range inside a live,
/// readable mapping; `len` is a multiple of `page_size`.
///
/// # Errors
///
/// - `Os` with phase `VerifyPlacement` if the range check fails for a reason
///   other than a refused page.
/// - `PageStatusError` if a page's node query fails.
/// - `WrongNode` if a page is resident outside `nodes`.
pub(crate) unsafe fn verify_chunk<P: Platform>(
    platform: &P,
    region: Region,
    start: NonNull<u8>,
    len: usize,
    page_size: usize,
    first_page: usize,
    nodes: &NodeMask,
) -> Result<(), InitError> {
    // SAFETY: forwarded from a caller holding the same guarantee.
    match unsafe { platform.check_bound(start, len, nodes) } {
        Ok(()) => return Ok(()),
        Err(OsCode(libc::EIO)) => {}
        Err(code) => {
            return Err(InitError::Os {
                phase: InitPhase::VerifyPlacement,
                region,
                code,
            });
        }
    }
    for index in 0..len / page_size {
        let page = first_page + index;
        // SAFETY: `index * page_size < len`, so the address is a page start
        // inside the chunk of the live, readable mapping.
        let node = unsafe { platform.page_node(start.add(index * page_size)) }
            .map_err(|code| InitError::PageStatusError { region, page, code })?;
        if !nodes.contains(node) {
            return Err(InitError::WrongNode { region, page, node });
        }
    }
    Ok(())
}
