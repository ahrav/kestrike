//! `ExtentAllocator` reserves and returns space using a bitmap, run summaries, and a capped run index stored in caller-provided fixed tables.
//!
//! A call counts work in visits, one unit per step: one per bitmap word and summary node a search or a held check reads, the reads a full recomputation of the summaries it updates makes (see the `bitmap` module), and the index steps the `index` module counts: one per node a descent, a leaf walk or a path rebuild reads, one per first leaf read, two per level a split or a refill touches and one per new root.
//! A visit counts one step of work, including writes to nodes the step read and reads of the root record's tree mask and tree roots; an empty-tree lookup counts zero visits.

use super::super::budget::{BudgetExhausted, WorkBudget, WorkKind};
use super::super::device::IO_UNIT;
use super::super::ledger::LedgerOverflow;
use super::bitmap::{
    CHUNK, CHUNK_WORDS, Change, FANOUT, LEVEL_LIMIT, edge_chunk, levels, space_base,
};
use super::index::{
    Found, IndexHeads, MAX_HEIGHT, NONE, RunNode, SATURATED, Step, TREES, index_height,
    index_nodes, key_run, run_key, tree_of,
};
use super::locator::{ExtentLocator, LOCATOR_LEN_LIMIT, LOCATOR_START_LIMIT, pack};
use super::partition::{HeldPhase, RawPartition};
use super::plan;

/// The allocator's header record.
///
/// [`ExtentAllocator::init`] overwrites every field, so the caller may pass any value; every later view reads the geometry and the index state it wrote.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ExtentRoot {
    pub(super) ledger: RawPartition,
    pub(super) payload_units: u64,
    /// Word offsets of the summary levels, as [`space_base`] computes them.
    pub(super) base: [u64; LEVEL_LIMIT + 1],
    pub(super) levels: u32,
    pub(super) index: IndexHeads,
    /// Runs a full index has left out since initialization; while it is zero the index holds every maximal free run.
    pub(super) drops: u64,
    /// The lowest chunk with fewer than [`CHUNK_WORDS`] words or an ancestor below the root with fewer than [`FANOUT`] children, as [`edge_chunk`] computes it: the chunk count when no chunk qualifies, and zero for a one-level volume; a one-chunk summary pass below it takes its visit count in closed form.
    pub(super) edge: u64,
    /// The full-extent charge `c` in units, positive, fixed by [`ExtentAllocator::init`] and kept by [`ExtentAllocator::restore_runs`].
    pub(super) charge: u64,
    /// `placeable` sums [`plan::placeable`]`(len, charge)` over the maximal free runs, where `len` is each run's length; the sum is at most the free units.
    pub(super) placeable: u64,
}

/// The refusal an allocator constructor reports for its volume size, full-extent charge, index capacity, tables or held extents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtentConfigError {
    ZeroUnits,
    /// The full-extent charge is zero.
    ZeroCharge,
    /// The payload holds more units than a locator start can name.
    VolumeTooLarge {
        payload_units: u64,
    },
    /// The space table holds `len` words where the volume's bitmap and summaries take `needed`.
    SpaceLength {
        len: usize,
        needed: usize,
    },
    /// The index capacity is zero, or its node table would reach `2^32 - 1` nodes, the null link.
    IndexCapacity {
        capacity: usize,
    },
    /// The node table holds `len` nodes where an index of the requested capacity takes `needed`.
    IndexLength {
        len: usize,
        needed: usize,
    },
    /// The held run starting at `start` is empty, overlaps or precedes the one before it, or ends past the payload; or, at `start` equal to the payload's units, the held runs hold other than the caller's unit total or fewer bytes than its payload total.
    Held {
        start: u64,
    },
}

/// A reservation refused; the bitmap, the summaries, the index, the placeable count and the ledger are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtentRefusal {
    /// `units` is zero or at least `2^24`, or `payload` exceeds `units` whole units.
    Length { units: u32, payload: usize },
    /// The budget holds fewer steps than the caller's work limit; it is unchanged.
    BudgetExhausted,
    /// No free run holds `units` units, or the search passed the work limit; the visits the search made, at most the limit, are debited.
    NoFit { units: u32 },
    /// The ledger refused the transition, which a conserved ledger never does; the search's visits are debited.
    Ledger,
}

/// A return refused; the bitmap, the summaries, the index, the placeable count and the ledger are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtentStateError {
    /// The extent is empty, reaches past the volume, or covers a free unit.
    NotHeld,
    /// The ledger's terms cannot cover the payload in the phase the caller named and the extent's waste.
    Ledger,
}

impl From<BudgetExhausted> for ExtentRefusal {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

impl From<LedgerOverflow> for ExtentRefusal {
    fn from(_: LedgerOverflow) -> Self {
        Self::Ledger
    }
}

impl From<LedgerOverflow> for ExtentStateError {
    fn from(_: LedgerOverflow) -> Self {
        Self::Ledger
    }
}

/// Entries of the run index for `slot_count` slots: `slot_count.div_ceil(8)`, at least one for any validated slot count.
pub(crate) fn index_capacity(slot_count: usize) -> usize {
    slot_count.div_ceil(8)
}

/// Nodes of the run index's table for `slot_count` slots: [`index_nodes`] of [`index_capacity`].
pub(crate) fn index_table_nodes(slot_count: usize) -> usize {
    index_nodes(index_capacity(slot_count))
}

/// `space_words` counts the bitmap words and every summary-level word for a payload of `payload_units` units.
pub(crate) fn space_words(payload_units: u64) -> usize {
    let (base, levels) = space_base(payload_units);
    base[levels] as usize
}

/// For `charge > 0`, `f(payload_units)` bounds the placeable units in every allocation state: `f(L) = L - L mod charge` satisfies `f(a) + f(b) <= f(a + b)`, and total free units are at most `payload_units`.
pub(crate) fn empty_placeable(payload_units: u64, charge: u64) -> u64 {
    plan::placeable(payload_units, charge)
}

/// The most visits one reservation or return of an extent of at most `record_units` units can make on a volume of `payload_units` units with `slot_count` slots.
pub(crate) fn work_bound(payload_units: u64, slot_count: usize, record_units: u64) -> usize {
    bound(payload_units, index_capacity(slot_count), record_units)
}

/// [`work_bound`] for an index of `capacity` entries.
///
/// With `h` the inner levels one tree of the index reaches at most ([`index_height`]), `d` summary levels above the chunks, `w` bitmap words per chunk (at most 8) and `c` the chunks an extent of at most `record_units` units touches, `min(record_units / CHUNK + 2, volume_chunks)`:
/// a best-fit lookup costs `3h + 1`, a descent `h + 1`, a removal `3h`, an insertion at a found position `2h + 3`, an offer to a full index the minimum's first-leaf read, a removal, a descent and an insertion, a run-end search `w + 7d`, a held check `c w` and a summary update `c (w + 8d)`.
/// A take and a fallback each visit a fixed part plus the summary update, and a return visits its fixed part plus the update and the held check; the bound is the largest of the three.
pub(super) fn bound(payload_units: u64, capacity: usize, record_units: u64) -> usize {
    let depth = levels(payload_units) as u64 - 1;
    let words = payload_units.div_ceil(64).min(CHUNK_WORDS);
    let height = index_height(capacity);
    let lookup = 3 * height + 1;
    let descent = height + 1;
    let remove = 3 * height;
    let insert = descent + 2 * height + 3;
    let offer = 1 + remove + insert;
    let run_end = words + (FANOUT - 1) * depth;
    let update = words + FANOUT * depth;
    let root = 1;
    let first_fit = FANOUT * depth + words;
    let take = root + lookup + run_end + remove + insert;
    let fallback = root + lookup + first_fit + run_end + offer;
    let reserve_fixed = take.max(fallback);
    let give_fixed = 2 * run_end + descent + 2 * (descent + remove) + offer;
    let chunks = (record_units / CHUNK + 2).min(payload_units.div_ceil(CHUNK));
    (reserve_fixed + chunks * update).max(give_fixed + chunks * (words + update)) as usize
}

/// What a run reservation placed: `taken >= 1` adjoining extents from
/// `first`, each of `first`'s units, then the tail extent right after them
/// when the call placed it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Run {
    pub first: ExtentLocator,
    pub taken: u32,
    pub tail: Option<ExtentLocator>,
}

/// Where a search placed a reservation.
enum Fit {
    /// The indexed run `start..start + len`, its length exact.
    Indexed { found: Found, start: u64, len: u64 },
    /// The first fit at `start`, which begins the unindexed maximal run `start..high`.
    Fallback { start: u64, high: u64 },
}

/// The extent allocator of one volume, over tables it borrows and never grows.
///
/// The module's bitmap, summary, index, placeable-count and ledger invariants hold after every call. A reservation resets `work` after its checks and budget preflight, and a return resets it before its checks; each then counts its visits.
#[derive(Debug)]
pub(crate) struct ExtentAllocator<'t> {
    pub(super) root: &'t mut ExtentRoot,
    pub(super) space: &'t mut [u64],
    pub(super) nodes: &'t mut [RunNode],
    pub(super) work: usize,
    /// The inner nodes and children of the last descent, from a tree's root down.
    /// A split, a traced removal and a leaf walk read it, so each requires the path of the descent that produced its position or entry to be the most recent one.
    pub(super) path: [Step; MAX_HEIGHT],
}

impl<'t> ExtentAllocator<'t> {
    /// `init` initializes the tables in place with one free run of `payload_units` units, a `capacity`-entry index over `nodes`, a ledger recording `metadata_units` metadata units and `payload_units` free units, and the full-extent charge `charge`.
    ///
    /// # Errors
    ///
    /// Checked in this order, each before any table is written:
    /// - `ZeroUnits` if `payload_units == 0`.
    /// - `ZeroCharge` if `charge == 0`.
    /// - `VolumeTooLarge` if `payload_units > LOCATOR_START_LIMIT`.
    /// - `SpaceLength` if `space.len()` differs from [`space_words`]`(payload_units)`.
    /// - `IndexCapacity` if `capacity` is zero or its [`index_nodes`] reach `2^32 - 1`.
    /// - `IndexLength` if `nodes.len()` differs from [`index_nodes`]`(capacity)`.
    pub fn init(
        payload_units: u64,
        metadata_units: u64,
        capacity: usize,
        charge: u64,
        root: &'t mut ExtentRoot,
        space: &'t mut [u64],
        nodes: &'t mut [RunNode],
    ) -> Result<Self, ExtentConfigError> {
        let mut allocator = Self::blank(
            (payload_units, metadata_units, capacity, charge),
            root,
            space,
            nodes,
        )?;
        let mut counts = [0; TREES];
        counts[tree_of(run_key(0, payload_units))] = 1;
        let placeable = empty_placeable(payload_units, charge);
        allocator.fill(std::iter::once((0, payload_units)), &counts, placeable);
        Ok(allocator)
    }

    /// `blank` checks the tables as [`init`](Self::init) documents, then writes the state both constructors start from: every unit taken and every summary zero, the root's geometry and charge, a placeable count of zero, an empty `capacity`-entry index, and a ledger whose payload is all free.
    fn blank(
        (payload_units, metadata_units, capacity, charge): (u64, u64, usize, u64),
        root: &'t mut ExtentRoot,
        space: &'t mut [u64],
        nodes: &'t mut [RunNode],
    ) -> Result<Self, ExtentConfigError> {
        if payload_units == 0 {
            return Err(ExtentConfigError::ZeroUnits);
        }
        if charge == 0 {
            return Err(ExtentConfigError::ZeroCharge);
        }
        if payload_units > LOCATOR_START_LIMIT {
            return Err(ExtentConfigError::VolumeTooLarge { payload_units });
        }
        let (base, levels) = space_base(payload_units);
        let needed = base[levels] as usize;
        if space.len() != needed {
            return Err(ExtentConfigError::SpaceLength {
                len: space.len(),
                needed,
            });
        }
        let needed = index_nodes(capacity);
        if capacity == 0 || needed >= NONE as usize {
            return Err(ExtentConfigError::IndexCapacity { capacity });
        }
        if nodes.len() != needed {
            return Err(ExtentConfigError::IndexLength {
                len: nodes.len(),
                needed,
            });
        }
        space.fill(0);
        // Bounded by `LOCATOR_START_LIMIT` units of 4 KiB, 2^49 bytes.
        let payload_bytes = payload_units as usize * IO_UNIT;
        *root = ExtentRoot {
            ledger: RawPartition::new(metadata_units as usize * IO_UNIT, payload_bytes),
            payload_units,
            base,
            levels: levels as u32,
            index: IndexHeads::default(),
            drops: 0,
            edge: edge_chunk(payload_units),
            charge,
            placeable: 0,
        };
        let mut allocator = Self::attach(root, space, nodes);
        allocator.index_init(capacity);
        Ok(allocator)
    }

    /// `fill` starts from a bitmap whose every unit is taken, and marks free each run of `runs`, the nonempty maximal free runs in address order.
    /// `fill` builds the chunk summaries and places the index keys in one pass, then builds the upper summaries and links the index trees; `counts` gives each index tree's run count.
    /// Each caller passes in `placeable` the sum of [`plan::placeable`] over `runs` at the root's charge, and `fill` stores it as the root's placeable count; debug builds check the sum against the runs.
    fn fill(
        &mut self,
        runs: impl Iterator<Item = (u64, u64)>,
        counts: &[u64; TREES],
        placeable: u64,
    ) {
        let (mut filling, mut open, mut sum) = (self.fill_plan(counts), None, 0);
        for (start, len) in runs {
            self.summarize_run(&mut open, start, len);
            self.fill_run(&mut filling, start, len);
            if cfg!(debug_assertions) {
                sum += plan::placeable(len, self.root.charge);
            }
        }
        debug_assert_eq!(placeable, sum, "the caller's sum matches the runs");
        self.root.placeable = placeable;
        self.summarize_end(open);
        self.fill_end(&filling);
        self.debug_check_placeable();
        self.work = 0;
    }

    /// `restored_runs` initializes the tables with every unit of `held` held, every other unit free and the full-extent charge `charge`: `held` lists half-open unit ranges in ascending, pairwise-disjoint order inside the payload that hold `units_held` units and `payload_held` payload bytes. One checked reserve and one publish move the held units out of the free term, their payload bytes into resident and the rest into waste; the capped index holds the largest free runs of the complement, as offering each run in address order leaves it.
    ///
    /// The warm bootstrap passes the maximal runs of the held bitmap its restored entries marked; every later reservation searches the bitmap `restored_runs` filled.
    ///
    /// # Errors
    ///
    /// `VolumeTooLarge` for a payload past `LOCATOR_START_LIMIT` units; `Held` at its start for a range that is empty, out
    /// of order, overlaps the one before it or ends past the payload, and `Held` at `payload_units` when the ranges hold
    /// other than `units_held` units or `payload_held` exceeds their bytes; [`init`](Self::init)'s refusals; each before
    /// any table is written.
    pub(crate) fn restored_runs(
        (payload_units, metadata_units, capacity, charge): (u64, u64, usize, u64),
        (root, space, nodes): (&'t mut ExtentRoot, &'t mut [u64], &'t mut [RunNode]),
        held: impl Iterator<Item = (u64, u64)> + Clone,
        (units_held, payload_held): (usize, usize),
    ) -> Result<Self, ExtentConfigError> {
        if payload_units > LOCATOR_START_LIMIT {
            return Err(ExtentConfigError::VolumeTooLarge { payload_units });
        }
        // Tree 0 holds the free runs of at least `TREES` units and tree `t` the runs of exactly `t` units for `0 < t < TREES`. The pass that checks the held ranges also counts the free run before each and the one after the last, and sums `plan::placeable(len, c)` for tree 0's runs; `counts[t] * plan::placeable(t, c)` then joins the sum for each exact-length tree. The pass precedes the charge check in `blank`, so `c = charge.max(1)` keeps the divisor positive; `fill` receives the sum only after that check passes, when `c == charge`.
        let (mut counts, mut placeable, c) = ([0; TREES], 0, charge.max(1));
        let mut count = |start: u64, len: u64| {
            if len > 0 {
                counts[tree_of(run_key(start, len))] += 1;
                if len >= TREES as u64 {
                    placeable += plan::placeable(len, c);
                }
            }
        };
        let (mut free, mut summed) = (0, 0u64);
        for (start, end) in held.clone() {
            if start < free || end <= start || end > payload_units {
                return Err(ExtentConfigError::Held { start });
            }
            count(free, start - free);
            (free, summed) = (end, summed + (end - start));
        }
        count(free, payload_units - free);
        if summed != units_held as u64 {
            return Err(ExtentConfigError::Held {
                start: payload_units,
            });
        }
        // `units_held` now equals the runs' units, which lie inside a payload of at most `LOCATOR_START_LIMIT` units,
        // so their bytes fit `usize`.
        let bytes = units_held * IO_UNIT;
        if payload_held > bytes {
            return Err(ExtentConfigError::Held {
                start: payload_units,
            });
        }
        let runs = held
            .chain([(payload_units, payload_units)])
            .scan(0, |free, (start, end)| {
                let run = (*free, start - *free);
                *free = end;
                Some(run)
            })
            .filter(|&(_, len)| len > 0);
        for (len, runs) in (0..).zip(&counts).skip(1) {
            placeable += runs * plan::placeable(len, c);
        }
        let shape = (payload_units, metadata_units, capacity, charge);
        let mut allocator = Self::blank(shape, root, space, nodes)?;
        let ledger = (allocator.root.ledger).reserve(bytes, payload_held);
        let Ok(ledger) = ledger.and_then(|ledger| ledger.publish(payload_held)) else {
            unreachable!(
                "held units={units_held} payload={payload_held} must fit the free term; ledger={:?}",
                allocator.root.ledger
            )
        };
        allocator.root.ledger = ledger;
        allocator.fill(runs, &counts, placeable);
        Ok(allocator)
    }

    /// `restore_runs` runs [`restored_runs`](Self::restored_runs) over tables a prior [`init`](Self::init) sized, keeping their payload units, metadata units, index capacity and charge, each read before the blank state overwrites the root; it returns true when the runs and totals are valid and the root's charge is positive.
    pub(crate) fn restore_runs(
        (root, space, nodes): (&'t mut ExtentRoot, &'t mut [u64], &'t mut [RunNode]),
        held: impl Iterator<Item = (u64, u64)> + Clone,
        totals: (usize, usize),
    ) -> bool {
        let shape = Self::shape_of(root);
        Self::restored_runs(shape, (root, space, nodes), held, totals).is_ok()
    }

    /// The payload units, metadata units, index capacity and charge a prior [`init`](Self::init) set on `root`.
    fn shape_of(root: &ExtentRoot) -> (u64, u64, usize, u64) {
        let metadata_units = (root.ledger.metadata / IO_UNIT) as u64;
        (
            root.payload_units,
            metadata_units,
            root.index.capacity as usize,
            root.charge,
        )
    }

    /// A view over tables a prior [`init`](Self::init) initialized, as that call or a later one left them.
    ///
    /// The caller passes only tables `init` accepted for the same volume, so every invariant holds on the view because it held when the last view ended.
    /// Device writes and reads rely on the bitmap invariant: held extents are pairwise disjoint, so each slot's locator names units no other slot holds.
    pub(crate) fn attach(
        root: &'t mut ExtentRoot,
        space: &'t mut [u64],
        nodes: &'t mut [RunNode],
    ) -> Self {
        Self {
            root,
            space,
            nodes,
            work: 0,
            path: [Step::default(); MAX_HEIGHT],
        }
    }

    /// [`bound`] for an extent of `units` units on this volume and index.
    pub(super) fn bound_for(&self, units: u64) -> usize {
        bound(
            self.root.payload_units,
            self.root.index.capacity as usize,
            units,
        )
    }

    /// Reserves `units` units, with `payload` of them counted as payload bytes and the rest as waste, by the module's fit rule.
    ///
    /// The call preflights `limit`, refuses `NoFit` when its search's visits exceed it, and debits its visits capped at `limit`.
    /// The storage passes [`work_bound`] for this extent, which covers the search and every update after it, so a placed reservation debits every visit it counted.
    ///
    /// # Errors
    ///
    /// Checked in this order; every refusal leaves the tables and the ledger unchanged:
    /// - `Length` if `units == 0`, `units >= LOCATOR_LEN_LIMIT` or `payload > units * IO_UNIT`, before the preflight.
    /// - `BudgetExhausted` if `budget` holds fewer than `limit` steps; the budget is unchanged.
    /// - `NoFit` if no free run holds `units` units, which the root summary shows in one read, or the search passed `limit`.
    /// - `Ledger` if the ledger refuses the reservation.
    pub fn reserve(
        &mut self,
        units: u32,
        payload: usize,
        limit: usize,
        budget: &mut WorkBudget,
    ) -> Result<ExtentLocator, ExtentRefusal> {
        self.reserve_run(units, 1, payload, None, limit, budget)
            .map(|run| run.first)
    }

    /// Reserves up to `count` adjoining extents of `units` units each, with `payload` bytes of each counted as payload, from the start of the run the fit rule selects for one extent; extent `i` starts `i * units` units after the first.
    /// An indexed fit takes as many of the `count` extents as its run holds; a first-fit fallback takes one.
    /// A `tail` of `(units, payload)` adds one extent right after them when the call takes all `count`, the selected run is the tail's own best fit in the index, and the run's remainder holds the tail.
    /// The caller passes a `limit` that covers the search, the tail's index lookup and the updates for the whole span requested.
    /// [`reserve`](Self::reserve) inlines this call with `count` fixed at one.
    ///
    /// # Errors
    ///
    /// As for [`reserve`](Self::reserve), with `NoFit` judged for one extent of `units` units and `Ledger` for the whole span placed, and with `Length` also when `count == 0`, when `count * units` plus the tail's units reaches `LOCATOR_LEN_LIMIT`, or for a tail of no units or with a payload past its units.
    #[inline(always)]
    pub fn reserve_run(
        &mut self,
        units: u32,
        count: u32,
        payload: usize,
        tail: Option<(u32, usize)>,
        limit: usize,
        budget: &mut WorkBudget,
    ) -> Result<Run, ExtentRefusal> {
        let extent = units as usize * IO_UNIT;
        let (tail_units, tail_payload) = tail.unwrap_or((0, 0));
        let span = u64::from(units) * u64::from(count) + u64::from(tail_units);
        if units == 0
            || count == 0
            || span >= u64::from(LOCATOR_LEN_LIMIT)
            || payload > extent
            || tail.is_some_and(|_| tail_units == 0)
            || tail_payload > tail_units as usize * IO_UNIT
        {
            return Err(ExtentRefusal::Length { units, payload });
        }
        budget.preflight(limit)?;
        self.work = 0;
        let reserved = self.place(units, count, payload, tail, limit);
        budget
            .debit_n(WorkKind::Visit, plan::charged(self.work, limit))
            .expect("the preflight covered the work limit");
        reserved
    }

    /// [`reserve_run`](Self::reserve_run) after its checks and preflight, counting its visits in `work`.
    #[inline(always)]
    fn place(
        &mut self,
        units: u32,
        count: u32,
        payload: usize,
        tail: Option<(u32, usize)>,
        limit: usize,
    ) -> Result<Run, ExtentRefusal> {
        let n = u64::from(units);
        // The tail's fit, read before the search because a long fit's
        // descent records the path the removal reads.
        let tail_key = tail
            .and_then(|(m, _)| self.index_best_fit(u64::from(m)))
            .map(|found| found.key);
        let fit = self.search(n);
        let fit = match fit {
            Some(fit) if plan::within(self.work, limit) => fit,
            _ => return Err(ExtentRefusal::NoFit { units }),
        };
        self.prefetch(match fit {
            Fit::Indexed { start, .. } | Fit::Fallback { start, .. } => start,
        });
        let taken = match fit {
            // The minimum precedes the narrowing: a run can hold `2^32` or more extents of `n` units.
            Fit::Indexed { len, .. } if count > 1 => (len / n).min(u64::from(count)) as u32,
            _ => 1,
        };
        let full = n * u64::from(taken);
        let tail = match (&fit, tail) {
            (Fit::Indexed { found, len, .. }, Some((m, bytes)))
                if taken == count && tail_key == Some(found.key) && *len - full >= u64::from(m) =>
            {
                Some((m, bytes))
            }
            _ => None,
        };
        let (tail_units, tail_payload) = tail.unwrap_or((0, 0));
        let span = full + u64::from(tail_units);
        let ledger = self.root.ledger.reserve(
            span as usize * IO_UNIT,
            payload * taken as usize + tail_payload,
        )?;
        let start = match fit {
            Fit::Indexed { found, start, len } => {
                self.index_remove(found);
                self.mark(start, span, false);
                self.update(
                    start,
                    start + span,
                    Change::Split {
                        low: start,
                        start,
                        end: start + span,
                        high: start + len,
                    },
                );
                let (rest, rest_len) = plan::remainder(start, span, start + len);
                if rest_len > 0 {
                    self.index_insert(rest, rest_len);
                    self.split_placeable(len, rest_len);
                } else {
                    self.root.placeable -= plan::placeable(len, self.root.charge);
                }
                start
            }
            Fit::Fallback { start, high } => {
                self.mark(start, n, false);
                self.update(
                    start,
                    start + n,
                    Change::Split {
                        low: start,
                        start,
                        end: start + n,
                        high,
                    },
                );
                let (rest, rest_len) = plan::remainder(start, n, high);
                self.offer(rest, rest_len);
                self.split_placeable(high - start, rest_len);
                start
            }
        };
        self.root.ledger = ledger;
        self.debug_check_placeable();
        debug_assert!(
            self.work <= limit
                && self.work <= self.bound_for(span) + self.bound_for(u64::from(tail_units))
        );
        // Inside both limits: the start lies in a volume of at most 2^37 units, and lengths of 2^24 or more were refused above.
        Ok(Run {
            first: ExtentLocator::from_bits(pack(start, units)),
            taken,
            tail: tail.map(|(m, _)| ExtentLocator::from_bits(pack(start + full, m))),
        })
    }

    /// The placement of `n` units, leaving the tables unchanged: the smallest indexed key at least `(n, 0)`, else first fit, which then finds the maximal run around its start.
    /// An index miss with a root that shows a fitting run means every fitting run was dropped, so the first fit lies in an unindexed run.
    #[inline(always)]
    fn search(&mut self, n: u64) -> Option<Fit> {
        if self.longest_run() < n {
            return None;
        }
        if let Some(found) = self.index_best_fit(n) {
            let (start, mut len) = key_run(found.key);
            if len == SATURATED {
                len = self.free_after(start);
            }
            return Some(Fit::Indexed { found, start, len });
        }
        let start = self.first_fit(n)?;
        debug_assert!(
            start == 0 || self.space[((start - 1) / 64) as usize] >> ((start - 1) % 64) & 1 == 0,
            "the lowest fit starts a maximal free run"
        );
        let high = start + self.free_after(start);
        Some(Fit::Fallback { start, high })
    }

    /// `len` is the length of the maximal free run a reservation split, and `rest` the length of the run's free remainder.
    #[inline(always)]
    fn split_placeable(&mut self, len: u64, rest: u64) {
        let c = self.root.charge;
        self.root.placeable =
            self.root.placeable - plan::placeable(len, c) + plan::placeable(rest, c);
    }

    /// Debug builds check that the placeable count is at most the ledger's whole free units after `fill` and after a reservation or return updates `root.ledger`.
    fn debug_check_placeable(&self) {
        debug_assert!(
            self.root.placeable <= (self.root.ledger.free / IO_UNIT) as u64,
            "placeable {} exceeds free units {} at charge {}",
            self.root.placeable,
            self.root.ledger.free / IO_UNIT,
            self.root.charge,
        );
    }

    /// Moves `payload` bytes of a reserved extent to resident, when its record is published.
    ///
    /// # Errors
    ///
    /// `LedgerOverflow` when fewer than `payload` bytes are reserved or `resident` would overflow; the ledger is unchanged.
    pub fn publish(&mut self, payload: usize) -> Result<(), LedgerOverflow> {
        self.root.ledger = self.root.ledger.publish(payload)?;
        Ok(())
    }

    /// Moves `payload` bytes of a resident extent to retired, when its record retires.
    ///
    /// # Errors
    ///
    /// `LedgerOverflow` when fewer than `payload` bytes are resident or `retired` would overflow; the ledger is unchanged.
    pub fn retire(&mut self, payload: usize) -> Result<(), LedgerOverflow> {
        self.root.ledger = self.root.ledger.retire(payload)?;
        Ok(())
    }

    /// Returns the extent `locator` names, whose `payload` bytes sit in `phase`, to the free set.
    ///
    /// The extent's bits join any free neighbours into one run; the neighbours' index entries leave the index and the joined run is offered to it.
    /// The call counts its visits in `work`, at most [`work_bound`] for the extent, and debits nothing: the caller preflights that bound where it can refuse and debits the count, and a rollback returns uncharged.
    ///
    /// Validation rejects an empty or out-of-volume extent before reading the index, because [`index_position`](Self::index_position) requires an in-volume key.
    /// The index descent for the extent's own key runs before the held check, so its loads and the check's read of the extent's bitmap words are in flight together; an extent with a taken unit on each side hangs its entry at the position found while the index has a spare entry.
    ///
    /// The held check reads the extent's bits: it refuses an extent with a free unit, which catches a second return and a locator past any held extent's end.
    /// The check proves every unit is held and takes slot ownership from the locator, so a locator naming units another slot holds passes it; the slot record's locator is written under the gate by the claim, or by a restored install from a validated, pairwise-disjoint held set whose extents the allocator holds before any restored slot publishes, retires or returns (the warm hold rebuilds the allocator before its installs), and device reads and writes trust the same locator.
    ///
    /// # Errors
    ///
    /// Each refusal leaves the tables and the ledger unchanged:
    /// - `NotHeld` if the extent is empty, reaches past the volume or covers a free unit.
    /// - `Ledger` if the ledger's terms cannot cover `payload` bytes in `phase` and the extent's waste.
    pub fn release(
        &mut self,
        locator: ExtentLocator,
        phase: HeldPhase,
        payload: usize,
    ) -> Result<(), ExtentStateError> {
        let (start, len) = (locator.start_unit(), u64::from(locator.len_units()));
        let end = start + len;
        self.work = 0;
        self.prefetch(start);
        if len == 0 || end > self.root.payload_units {
            return Err(ExtentStateError::NotHeld);
        }
        let own = self.index_position(run_key(start, len));
        if !self.taken(start, len) {
            return Err(ExtentStateError::NotHeld);
        }
        let ledger = self
            .root
            .ledger
            .release(phase, len as usize * IO_UNIT, payload)?;
        self.mark(start, len, true);
        let (low, high) = plan::joined(start, end, self.free_before(start), self.free_after(end));
        self.update(start, end, Change::Joined { low, high });
        let c = self.root.charge;
        if low == start && high == end {
            self.offer_at(start, len, own);
            self.root.placeable += plan::placeable(len, c);
        } else {
            self.unindex(low, start - low);
            self.unindex(end, high - end);
            self.offer(low, high - low);
            self.root.placeable = self.root.placeable + plan::placeable(high - low, c)
                - plan::placeable(start - low, c)
                - plan::placeable(high - end, c);
        }
        self.root.ledger = ledger;
        self.debug_check_placeable();
        debug_assert!(self.work <= self.bound_for(len));
        Ok(())
    }

    pub fn ledger(&self) -> RawPartition {
        self.root.ledger
    }

    /// Visits the last reservation or return counted.
    pub fn visits(&self) -> usize {
        self.work
    }

    /// Runs a full index has left out since initialization.
    pub fn drops(&self) -> u64 {
        self.root.drops
    }

    /// Free units in whole full extents: the sum over the maximal free runs of each run's largest multiple of the charge.
    pub fn placeable(&self) -> u64 {
        self.root.placeable
    }
}

#[cfg(test)]
impl ExtentAllocator<'_> {
    /// Sets the ledger's free term to `free` bytes and returns the term it replaced, for a plant whose reservations the ledger refuses while the bitmap still holds a free run.
    pub(crate) fn plant_ledger_free(&mut self, free: usize) -> usize {
        std::mem::replace(&mut self.root.ledger.free, free)
    }

    /// Sets the root's summary level count to `levels` and returns the count it replaced, for a plant of a malformed root that a read of the longest free run panics on.
    pub(crate) fn plant_levels(&mut self, levels: u32) -> u32 {
        std::mem::replace(&mut self.root.levels, levels)
    }

    /// Free runs as `(start, len)` in address order, read from the bitmap alone.
    pub(crate) fn free_set(&self) -> Vec<(u64, u64)> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        let mut extend = |unit: u64, len: u64| match runs.last_mut() {
            Some((start, run)) if *start + *run == unit => *run += len,
            _ => runs.push((unit, len)),
        };
        for (index, &x) in self.space[..self.root.base[0] as usize].iter().enumerate() {
            let base = index as u64 * 64;
            if x == u64::MAX {
                extend(base, 64);
                continue;
            }
            let mut bit = 0;
            while bit < 64 {
                let rest = x >> bit;
                if rest == 0 {
                    break;
                }
                let skip = u64::from(rest.trailing_zeros());
                let ones = u64::from((rest >> skip).trailing_ones());
                extend(base + bit + skip, ones);
                bit += skip + ones;
            }
        }
        runs
    }

    /// The indexed runs as `(start, len)` in address order, asserting that each key names a maximal free run of the bitmap.
    pub(crate) fn indexed_runs(&self) -> Vec<(u64, u64)> {
        let free = self.free_set();
        let mut runs: Vec<(u64, u64)> = self
            .index_keys()
            .into_iter()
            .map(|key| {
                let (start, len) = key_run(key);
                let at = free
                    .binary_search_by_key(&start, |run| run.0)
                    .expect("an indexed key starts a maximal run");
                let exact = free[at].1;
                assert_eq!(
                    len,
                    exact.min(SATURATED),
                    "an indexed key names a maximal run"
                );
                (start, exact)
            })
            .collect();
        runs.sort_unstable();
        runs
    }

    pub(super) fn capacity(&self) -> usize {
        self.root.index.capacity as usize
    }

    /// Asserts the module's invariants: the ledger against the set bits, the placeable count against the free runs, the clear tail, every summary against the bitmap, the index's tree shape and entries, and an index that holds every free run while nothing was dropped.
    pub(crate) fn check(&self, metadata_units: u64) {
        let free = self.free_set();
        assert_eq!(
            self.longest_free_run(),
            free.iter().map(|run| run.1).max().unwrap_or(0),
            "the longest-run accessor matches the free bitmap"
        );
        let free_units: u64 = free.iter().map(|run| run.1).sum();
        let c = self.root.charge;
        assert_eq!(
            self.root.placeable,
            free.iter().map(|run| run.1 / c * c).sum::<u64>(),
            "the placeable count sums each free run's whole charges"
        );
        assert!(
            self.root.placeable <= free_units,
            "the placeable count is at most the free units"
        );
        assert_eq!(
            self.root.ledger.free,
            free_units as usize * IO_UNIT,
            "set bits count the free units"
        );
        let ledger = self.root.ledger;
        assert_eq!(
            [
                ledger.free,
                ledger.reserved,
                ledger.resident,
                ledger.retired,
                ledger.waste
            ]
            .iter()
            .sum::<usize>(),
            self.root.payload_units as usize * IO_UNIT,
            "the payload terms sum to the allocator's units"
        );
        assert_eq!(
            ledger.metadata,
            metadata_units as usize * IO_UNIT,
            "the metadata term holds the volume's prefix"
        );
        let words = self.root.base[0] as usize;
        let tail = self.root.payload_units % 64;
        if tail != 0 {
            assert_eq!(
                self.space[words - 1] >> tail,
                0,
                "bits past the volume stay clear"
            );
        }
        self.summaries_check(&free);
        self.index_check();
        let indexed = self.indexed_runs();
        if self.root.drops == 0 {
            assert_eq!(
                indexed, free,
                "an index that dropped nothing holds every free run"
            );
        }
    }

    /// Asserts every summary equals the one `free`, the bitmap's maximal runs in address order, gives over the node's span.
    pub(super) fn summaries_check(&self, free: &[(u64, u64)]) {
        let units = self.root.payload_units;
        for level in 0..self.levels() {
            let span = super::bitmap::span(level);
            let mut runs = free.iter().peekable();
            for node in 0..self.nodes(level) {
                let (low, high) = (node * span, (node + 1) * span);
                let mut expected = super::summary::Summary::default();
                while let Some(&&(start, len)) = runs.peek() {
                    let (from, to) = (start.max(low), (start + len).min(high).min(units));
                    if from < to {
                        expected.max = expected.max.max(to - from);
                        if from == low {
                            expected.start = to - from;
                        }
                        if to == high {
                            expected.end = to - from;
                        }
                    }
                    if start + len > high {
                        break;
                    }
                    runs.next();
                }
                assert_eq!(self.decode(level, node), expected, "summary {level}/{node}");
            }
        }
    }
}
