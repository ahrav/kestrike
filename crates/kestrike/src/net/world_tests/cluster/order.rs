//! The ordering plants of three cluster controls. Each selects at most one
//! read according to session-event order.
//!
//! A plant watches the first upload, version 0, of the run's hot key and
//! the GETs of that key, through three session events. I(c) is client c's
//! session accepting a GET of the key, which numbers the GET. R(c) is
//! client c's session returning the outcome of a GET of the key. P is the
//! first publication report for version 0 of the hot key.
//! [`Order::decided`] selects a complete read of version 0 whose GET
//! satisfies all d ordering constraints of a depth-d plant:
//!
//! - Depth 1 selects a GET of either client with I before P.
//! - Depth 2 selects a GET of client 0 with I(0) before P and an R(1)
//!   before its R(0).
//! - Depth 3 selects a GET of client 0 with I(0) before P and, for one GET
//!   of client 1, I(0) before I(1) and R(1) before R(0).
//!
//! At every depth the selected read is decided after P: a read decided
//! before P selects nothing, and at depths 2 and 3 it still counts as an
//! R(1) when client 1 decided it. R(1) is any outcome of a GET of the hot
//! key by client 1, complete or otherwise, decided before or after P.
//!
//! Depth counts the constraints listed for each plant (the depth of
//! Burckhardt et al., *A Randomized Scheduler with Probabilistic
//! Guarantees of Finding Bugs*, ASPLOS 2010); the order of P before the
//! selected read, which each plant also needs, is common to the three
//! plants and stands outside the count. Every issue number
//! an [`Order`] compares comes from one counter, that of the partition
//! owning the hot key, which accepts every GET and upload of the key and
//! numbers its accepted GETs of every key. GETs accepted before P form
//! the plant's candidate set. Once the last of them is decided, a plant
//! that selected none selects none for the rest of the run.

use super::Plant;

/// The session events an ordering plant has seen for version 0 of the hot
/// key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Order {
    plant: Plant,
    hot: u8,
    /// The issue number of the latest GET accepted before P, once P
    /// happened.
    before_report: Option<u64>,
    /// The greatest issue number among the decided GETs of client 1.
    decided_by_one: Option<u64>,
    /// The plant selected a read.
    acted: bool,
}

impl Order {
    pub(super) fn new(plant: Plant, hot: u8) -> Self {
        Self {
            plant,
            hot,
            before_report: None,
            decided_by_one: None,
            acted: false,
        }
    }

    /// Records P when the published upload of `key` at `version` is the
    /// hot key's version 0. `issued` is the issue number of the latest GET
    /// the upload's partition accepted.
    pub(super) fn published(&mut self, key: u8, version: u32, issued: u64) {
        if key == self.hot && version == 0 {
            self.before_report.get_or_insert(issued);
        }
    }

    /// Records the decided GET of `key` by `client` with issue number
    /// `issued`, and returns `true` when the plant selects it. A GET
    /// decided before P is recorded and selects nothing. `read`
    /// yields the version a read returned when it completed with exactly
    /// the bytes an upload of the key wrote, and runs only for a GET of the
    /// hot key under an ordering plant.
    pub(super) fn decided(
        &mut self,
        client: usize,
        issued: u64,
        key: u8,
        read: impl FnOnce() -> Option<u32>,
    ) -> bool {
        if key != self.hot {
            return false;
        }
        let ordered = match self.plant {
            Plant::Depth1 => true,
            Plant::Depth2 => client == 0 && self.decided_by_one.is_some(),
            Plant::Depth3 => client == 0 && self.decided_by_one.is_some_and(|later| later > issued),
            Plant::None
            | Plant::WrongOwner
            | Plant::StaleRead
            | Plant::LateStale
            | Plant::Leak
            | Plant::Corrupt
            | Plant::Misread
            | Plant::Unremoved
            | Plant::LeakedUnit
            | Plant::Uncounted => return false,
        };
        let before = self.before_report.is_some_and(|latest| issued <= latest);
        if client == 1 {
            self.decided_by_one = self.decided_by_one.max(Some(issued));
        }
        let selects = !self.acted && before && ordered && read() == Some(0);
        self.acted |= selects;
        selects
    }
}
