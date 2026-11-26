//! [`Storage::holdings_into`] takes the pool gate once, with the quiet try,
//! and copies into buffers its caller keeps every slot's lifetime word, the
//! extents each held slot names, both ledgers, the membership of the
//! free-slot set and the allocator's free runs; it releases the gate before
//! it returns. [`Holdings::judge`] compares those tables with each other and
//! with the index bindings the caller read in the same controller action,
//! and returns the first fault in a fixed order.
//!
//! A `Filling`, `Resident` or `Retired` slot holds the one extent of a
//! direct locator, or the held prefix of its sequence block. With the pool
//! gate free, a live storage past any warm load satisfies the first four
//! rules below. The fifth, the binding rule, holds at a narrower point:
//! between controller actions, with every publication completed or
//! refused. A publication installs its anchor under the shard gate before
//! it stores the index pair, so a snapshot taken between those writes can
//! see an unbound live resident.
//!
//! - every slot word is well formed and names a state from `Free` through
//!   `Quarantined`;
//! - every held unit lies below the volume's payload units and is held by
//!   exactly one slot;
//! - the allocator's free runs are exactly the maximal runs of unheld
//!   units;
//! - the slot ledger counts each state's words, the free-slot set holds
//!   exactly the `Free` slots, with every bit past the last slot clear,
//!   and the raw ledger's free term is the free units' bytes;
//! - each binding names a distinct live resident at the binding's
//!   incarnation, and every live resident without `ABANDONED` is bound. A
//!   live resident is a well-formed `Resident` word with a nonzero count
//!   ([`live_resident`]).
//!
//! A pass establishes that these tables and the bindings agree at the
//! snapshot. These quantities take their own checks: whether an exit
//! released its claim, whether a length every table agrees on is right,
//! payload bytes per ledger category, the allocator's summaries and run
//! index, the free-slot set's summary levels, the sequence arena's free lists, pending index pairs and lease
//! credits, the metadata prefix, device and NIC custody, progress of
//! returns, and a fault made and repaired inside one action. The snapshot
//! decodes locators with [`Held::decode`] and the arena's `prefix`, the
//! decoders the return path uses, so a defect the two share passes the
//! judge.

use std::sync::atomic::Ordering;

use super::AllocationId;
use super::extent::{ExtentLocator, RawPartition};
use super::held::Held;
use super::layout::IO_UNIT;
use super::ledger::SlotPartition;
use super::lenses::{Binding, live_resident};
use super::os::Platform;
use super::owner::Storage;
use super::slot::Record;
use super::tables::{SlotIndex, Tables};
use super::word::{self, SlotState};

#[cfg(test)]
#[path = "conservation_tests.rs"]
mod tests;

/// One extent a held slot names, in payload units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Extent {
    pub(crate) start: u64,
    pub(crate) len: u64,
    pub(crate) slot: u32,
}

/// The first fault [`Holdings::judge`] finds, in its checking order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The snapshot's reason for leaving the tables unread.
    Unreadable(&'static str),
    /// `slot`'s word carries a reserved bit or a state encoding past
    /// `Quarantined`.
    Malformed {
        slot: u32,
    },
    /// An extent `slot` holds ends past the volume's payload units.
    PastVolume {
        slot: u32,
    },
    /// An extent `slot` holds shares a unit with another held extent.
    Overlap {
        slot: u32,
    },
    /// The allocator's free runs differ from the maximal runs of unheld
    /// units.
    FreeRuns,
    /// A slot ledger count differs from the number of words in its state.
    SlotCounts,
    /// `slot`'s membership of the free-slot set differs from whether its
    /// word is `Free`, or `slot` lies past the slot table and is in the set.
    FreeSlots {
        slot: u32,
    },
    /// The raw ledger's free term differs from the free units' bytes.
    RawFree,
    DuplicateBinding {
        slot: u32,
    },
    /// A binding names `slot`, which is past the slot table or whose word is
    /// other than a live resident whose incarnation's low 16 bits are the
    /// binding's.
    NotResident {
        slot: u32,
    },
    /// `slot` holds an unbound live resident without `ABANDONED`.
    UnboundResident {
        slot: u32,
    },
}

/// The tables [`Storage::holdings_into`] copied under one pool-gate hold,
/// with the judge's scratch. Every buffer keeps its capacity across
/// snapshots. A default buffer is unreadable until a snapshot fills it.
#[derive(Debug)]
pub(crate) struct Holdings {
    /// Why the snapshot could not read the tables. The other fields then
    /// hold what was copied before the stop, and `payload_units`, `slots`
    /// and `raw` may hold an earlier snapshot's values.
    pub(super) unreadable: Option<&'static str>,
    pub(super) payload_units: u64,
    pub(super) words: Vec<u64>,
    /// Every extent a `Filling`, `Resident` or `Retired` slot holds.
    pub(super) extents: Vec<Extent>,
    /// Whether the free-slot set holds each slot, in slot order, through
    /// the last bit of the set's last level-0 word.
    pub(super) free_slots: Vec<bool>,
    pub(super) free_runs: Vec<(u64, u64)>,
    pub(super) slots: SlotPartition,
    pub(super) raw: RawPartition,
    /// The bound slots in ascending order, which the judge fills.
    bound: Vec<u32>,
}

impl Default for Holdings {
    fn default() -> Self {
        Self {
            unreadable: Some(UNTAKEN),
            payload_units: 0,
            words: Vec::new(),
            extents: Vec::new(),
            free_slots: Vec::new(),
            free_runs: Vec::new(),
            slots: SlotPartition::default(),
            raw: RawPartition::default(),
            bound: Vec::new(),
        }
    }
}

const UNTAKEN: &str = "no snapshot filled the buffers";

const fn level0_words(slots: usize) -> usize {
    let words = slots.div_ceil(u64::BITS as usize);
    if words == 0 { 1 } else { words }
}

// For the listed slot counts, a single level-0 word accounts for the whole
// `free::words` count; otherwise each level-0 word counts as one slot of
// the levels above.
const _: () = {
    let counts = [0, 1, 63, 64, 65, 4096, 4097, 1 << 20];
    let mut at = 0;
    while at < counts.len() {
        let level0 = level0_words(counts[at]);
        let above = if level0 > 1 {
            super::free::words(level0)
        } else {
            0
        };
        assert!(super::free::words(counts[at]) == level0 + above);
        at += 1;
    }
};
const GATE: &str = "the pool gate was held or poisoned";
const NOT_LIVE: &str = "the storage was no longer live";
const WARM: &str = "the storage is inside a warm load";
const LOCATOR: &str = "a held slot's locator names neither form";
const SEQUENCE: &str = "a held slot's sequence block was refused";

/// `word`'s state, or `None` for a reserved bit or a state encoding past
/// `Quarantined`.
fn state_of(word: u64) -> Option<SlotState> {
    const FREE: u64 = SlotState::Free.bits();
    const FILLING: u64 = SlotState::Filling.bits();
    const RESIDENT: u64 = SlotState::Resident.bits();
    const RETIRED: u64 = SlotState::Retired.bits();
    const QUARANTINED: u64 = SlotState::Quarantined.bits();
    if !word::well_formed(word) {
        return None;
    }
    match word & word::STATE {
        FREE => Some(SlotState::Free),
        FILLING => Some(SlotState::Filling),
        RESIDENT => Some(SlotState::Resident),
        RETIRED => Some(SlotState::Retired),
        QUARANTINED => Some(SlotState::Quarantined),
        _ => None,
    }
}

fn extent(locator: ExtentLocator, slot: usize) -> Extent {
    Extent {
        start: locator.start_unit(),
        len: u64::from(locator.len_units()),
        slot: slot as u32,
    }
}

impl<P: Platform> Storage<P> {
    /// Copies the tables the judge reads into `out` under one quiet try of
    /// the pool gate, which it releases before returning. Sets
    /// `out.unreadable` for a busy or poisoned gate, a storage past its
    /// `Live` phase, a storage inside a warm load, a held locator of neither
    /// form or a sequence block the arena refuses. Of a slot whose word is
    /// malformed it copies the word alone, which the judge of a readable
    /// snapshot reports.
    pub(crate) fn holdings_into(&self, out: &mut Holdings) {
        out.unreadable = Some(UNTAKEN);
        out.words.clear();
        out.extents.clear();
        out.free_slots.clear();
        out.free_runs.clear();
        let Some(pool) = self.live_pool() else {
            out.unreadable = Some(NOT_LIVE);
            return;
        };
        let Ok(mut access) = pool.try_lock_quiet() else {
            out.unreadable = Some(GATE);
            return;
        };
        if pool.warm_hold.load(Ordering::Acquire) {
            access.release();
            out.unreadable = Some(WARM);
            return;
        }
        out.payload_units = pool.descriptor().geometry.payload_units();
        let mut tables = access.tables();
        out.slots = tables.state.ledger;
        let extents = tables.extents();
        out.raw = extents.ledger();
        extents.free_runs_into(&mut out.free_runs);
        let free = tables.free_slots();
        let records = pool.records();
        // Level 0 holds whole words, at least one, so the copy reaches the
        // bits past the last slot, which the set keeps clear.
        for slot in 0..level0_words(records.len()) * u64::BITS as usize {
            out.free_slots.push(free.contains(slot));
        }
        out.unreadable = copy_slots(records, &mut tables, out).err();
        access.release();
    }
}

/// Copies every slot's word into `out`, and the extents of each held slot,
/// in slot order, stopping at the first locator or sequence block it cannot
/// read and returning why. Of a slot whose word is malformed it copies the
/// word alone.
fn copy_slots(
    records: &[Record],
    tables: &mut Tables<'_>,
    out: &mut Holdings,
) -> Result<(), &'static str> {
    for (slot, record) in records.iter().enumerate() {
        let held = record.ident.load(Ordering::Acquire);
        out.words.push(held);
        let Some(state) = state_of(held) else {
            continue;
        };
        if matches!(state, SlotState::Free | SlotState::Quarantined) {
            continue;
        }
        match Held::decode(record.locator()).ok_or(LOCATOR)? {
            Held::Direct(locator) => out.extents.push(extent(locator, slot)),
            Held::Sequence { block, count } => {
                let owner = AllocationId::new(SlotIndex(slot), word::incarnation(held));
                let arena = tables.blocks();
                let prefix = arena.prefix(block, owner, count).map_err(|_| SEQUENCE)?;
                out.extents.extend(
                    prefix
                        .iter()
                        .map(|&bits| extent(ExtentLocator::from_bits(bits), slot)),
                );
            }
        }
    }
    Ok(())
}

impl Holdings {
    /// The first fault of this snapshot against `bindings`, in this order:
    /// unreadable, malformed word, past the volume, overlap, free runs, slot
    /// counts, free-slot set, raw free term, duplicate binding, binding to
    /// a slot other than a live resident, unbound resident. It sorts its
    /// own extent copy and writes its scratch.
    pub(crate) fn judge(&mut self, bindings: &[Binding]) -> Result<(), Fault> {
        if let Some(reason) = self.unreadable {
            return Err(Fault::Unreadable(reason));
        }
        self.bound.clear();
        self.bound
            .extend(bindings.iter().map(|binding| binding.identity.slot));
        self.bound.sort_unstable();
        // One pass over the slots gathers what the later checks report, so
        // each check below still reports in its own place in the order.
        let mut counted = SlotPartition::default();
        let (mut stray, mut unbound) = (None, None);
        for (slot, &held) in self.words.iter().enumerate() {
            let slot = slot as u32;
            let state = state_of(held).ok_or(Fault::Malformed { slot })?;
            *match state {
                SlotState::Free => &mut counted.free,
                SlotState::Filling => &mut counted.filling,
                SlotState::Resident => &mut counted.resident,
                SlotState::Retired => &mut counted.retired,
                SlotState::Quarantined => &mut counted.quarantined,
            } += 1;
            if stray.is_none()
                && self.free_slots.get(slot as usize) != Some(&(state == SlotState::Free))
            {
                stray = Some(slot);
            }
            if unbound.is_none()
                && live_resident(held)
                && held & word::ABANDONED == 0
                && self.bound.binary_search(&slot).is_err()
            {
                unbound = Some(slot);
            }
        }
        if let Some(extent) = self
            .extents
            .iter()
            .find(|extent| extent.start.saturating_add(extent.len) > self.payload_units)
        {
            return Err(Fault::PastVolume { slot: extent.slot });
        }
        self.extents.sort_unstable();
        if let Some(pair) = self
            .extents
            .windows(2)
            .find(|pair| pair[0].start + pair[0].len > pair[1].start)
        {
            return Err(Fault::Overlap { slot: pair[1].slot });
        }
        // The gaps before each held extent and before the volume's end are
        // the unheld runs, in address order.
        let (mut runs, mut cursor, mut free_units) = (0, 0, 0);
        for at in 0..=self.extents.len() {
            let (start, end) = match self.extents.get(at) {
                Some(extent) => (extent.start, extent.start + extent.len),
                None => (self.payload_units, self.payload_units),
            };
            if start > cursor {
                if self.free_runs.get(runs) != Some(&(cursor, start - cursor)) {
                    return Err(Fault::FreeRuns);
                }
                runs += 1;
                free_units += start - cursor;
            }
            cursor = end;
        }
        if runs != self.free_runs.len() {
            return Err(Fault::FreeRuns);
        }
        if counted != self.slots {
            return Err(Fault::SlotCounts);
        }
        if let Some(slot) = stray.or_else(|| {
            let mut past = self.free_slots.iter().enumerate().skip(self.words.len());
            past.find(|&(_, &free)| free).map(|(slot, _)| slot as u32)
        }) {
            return Err(Fault::FreeSlots { slot });
        }
        if self.raw.free as u64 != free_units * IO_UNIT as u64 {
            return Err(Fault::RawFree);
        }
        if let Some(pair) = self.bound.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(Fault::DuplicateBinding { slot: pair[0] });
        }
        if let Some(binding) = bindings.iter().find(|binding| {
            let identity = binding.identity;
            !self.words.get(identity.slot as usize).is_some_and(|&held| {
                live_resident(held) && word::incarnation(held) as u16 == identity.incarnation_low
            })
        }) {
            return Err(Fault::NotResident {
                slot: binding.identity.slot,
            });
        }
        if let Some(slot) = unbound {
            return Err(Fault::UnboundResident { slot });
        }
        Ok(())
    }
}
