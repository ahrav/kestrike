//! The pure checkpoint-slot placement check, which refuses a capture before any unit is submitted when every slot is unavailable or the entry count exceeds `N_max`.
//!
//! - SLOT-OUTSIDE-POSSIBLE: a placed slot lies outside `unavailable`, which the reservation passes as the tenure's possibly-named set (every slot the store names or an own Publish with an unresolved outcome may name), its quarantined slots and its reserved slot.
//! - A caller matches the prefix model's `capture` step when it defers other placements and success processing from a capture's placement until its Publish submission.

use crate::failover::records::{Layout, LayoutRefusal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementRefusal {
    Layout(LayoutRefusal),
    Entries { entries: u64, cap: u32 },
    NoFreeSlot,
}

/// The lowest slot outside `unavailable`. Passing only the slot the store names lets a capture overwrite the slot of an own Publish still in flight, and omitting the quarantine lets it overwrite a slot an earlier attempt may still land on.
pub fn place(layout: &Layout, unavailable: &[u32], entries: u64) -> Result<u32, PlacementRefusal> {
    layout.check_floor().map_err(PlacementRefusal::Layout)?;
    if entries > u64::from(layout.entries) {
        return Err(PlacementRefusal::Entries {
            entries,
            cap: layout.entries,
        });
    }
    (0..layout.slots)
        .find(|slot| !unavailable.contains(slot))
        .ok_or(PlacementRefusal::NoFreeSlot)
}
