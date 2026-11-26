//! Global observations of a composed world at stopped boundaries and at
//! teardown. A boundary compares the storage's index bindings, its slot
//! facts and the verified record each bound slot holds on raw media with
//! the registry of oracle-generated content, then judges the storage's
//! tables with the conservation rule, and the recorded rows cross the
//! cut through the oracle's continuation entry. The first failure any check
//! finds is written once into a shared cell that later failures leave as it
//! is.
//!
//! An [`Observer`] judges the world again when it drops, passively: it reads
//! through try-borrow and try-lock and the copy-only lenses, changes no
//! world state, and on normal return raises the cell's first failure once.
//! While a panic unwinds it never raises: it records the truncated history's
//! verdict beside the primary panic, whose payload propagates unchanged; a
//! truncated history that passes its checks is unsuccessful.
//!
//! Witnesses of composed scenarios are correlated: a required witness fires
//! only when every ingredient it requires was set for one correlation before
//! the fire, and an unfired or never-armed witness, or a capture it needed
//! that a bound dropped, leaves the case unsuccessful.

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
use std::sync::{Mutex, TryLockError};

use crate::oracle::{
    Continuation, Entry, Geometry, LIMITS, Label, Obligation, Ordinal, Owner, Pending, Row,
    Verdict, WideOp,
};
use crate::storage::conservation::{Fault, Holdings};
use crate::storage::lenses::{Binding, SlotFact};
use crate::storage::owner_fixture::{SimControl, TestPlatform};
use crate::storage::{AllocationId, SlotIndex, Storage};

/// One registered content: a key, a label the oracle published or may have
/// published there, and its payload, metadata then body, with the length of
/// the metadata.
#[derive(Debug)]
struct Content {
    key: [u8; 32],
    label: Label,
    metadata: u32,
    payload: Vec<u8>,
}

/// The oracle-generated content each key may hold, bounded.
/// [`prune`](Self::prune) removes content only at a validated oracle cut;
/// [`retire`](Self::retire) removes content the caller's own checker
/// discharged.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    entries: Vec<Content>,
    limit: usize,
    /// The most entries held at once.
    peak: usize,
    overflow: bool,
    /// A label registered twice with different payloads.
    conflict: bool,
}

impl Registry {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    pub(crate) fn register(
        &mut self,
        key: [u8; 32],
        label: Label,
        metadata: u32,
        payload: Vec<u8>,
    ) {
        if let Some(known) = self.entries.iter().find(|entry| entry.label == label) {
            self.conflict |=
                (known.key, known.metadata, &known.payload) != (key, metadata, &payload);
            return;
        }
        if self.entries.len() == self.limit {
            self.overflow = true;
            return;
        }
        self.entries.push(Content {
            key,
            label,
            metadata,
            payload,
        });
        self.peak = self.peak.max(self.entries.len());
    }

    /// Whether `key` holds any registered content.
    pub(crate) fn knows(&self, key: &[u8; 32]) -> bool {
        self.entries.iter().any(|entry| entry.key == *key)
    }

    /// Whether a registered content of `key` has a body, its payload past
    /// its metadata, that `fits`.
    fn body(&self, key: &[u8; 32], fits: impl Fn(&[u8]) -> bool) -> bool {
        self.entries
            .iter()
            .filter(|entry| entry.key == *key)
            .filter_map(|entry| entry.payload.get(entry.metadata as usize..))
            .any(fits)
    }

    /// Whether `bytes` is the whole body of a registered content of `key`.
    pub(crate) fn serves(&self, key: &[u8; 32], bytes: &[u8]) -> bool {
        self.body(key, |body| body == bytes)
    }

    /// Whether `bytes` is a prefix of the body of a registered content of
    /// `key`.
    pub(crate) fn starts(&self, key: &[u8; 32], bytes: &[u8]) -> bool {
        self.body(key, |body| body.starts_with(bytes))
    }

    /// The label of `key`'s registered content whose metadata length is
    /// `metadata` and whose payload is `payload`, if any.
    pub(crate) fn label(&self, key: &[u8; 32], metadata: u32, payload: &[u8]) -> Option<Label> {
        self.entries
            .iter()
            .find(|entry| {
                entry.key == *key && entry.metadata == metadata && entry.payload == payload
            })
            .map(|entry| entry.label)
    }

    /// Whether `payload`, framed with `metadata` metadata bytes, is a
    /// registered content of `key`.
    fn holds(&self, key: &[u8; 32], metadata: u32, payload: &[u8]) -> bool {
        self.label(key, metadata, payload).is_some()
    }

    /// Keeps only the entries `keep` selects, once `cuts` last validated a
    /// passing cut through all `rows` rows recorded; returns whether it
    /// pruned.
    pub(crate) fn prune(
        &mut self,
        (cuts, rows): (&Cuts, usize),
        keep: impl Fn(&[u8; 32], Label) -> bool,
    ) -> bool {
        if !cuts.passed() || cuts.fed != rows {
            return false;
        }
        self.retire(keep);
        true
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// The most entries the registry held at once.
    pub(crate) fn peak(&self) -> usize {
        self.peak
    }

    /// Keeps only the entries `keep` selects. The caller retires only
    /// content its own checker discharged: content no later check can need.
    pub(crate) fn retire(&mut self, keep: impl Fn(&[u8; 32], Label) -> bool) {
        self.entries.retain(|entry| keep(&entry.key, entry.label));
    }
}

/// A bound slot's record fails its header or chunk checks for the slot's
/// allocation and the media's session.
pub(crate) const UNCHECKED_RECORD: &str = "a bound slot's record fails its header or chunk checks";

/// A bound slot's payload or framing matches none of its key's registered
/// content.
pub(crate) const UNREGISTERED_BYTES: &str = "a bound slot's bytes match no registered content";

/// Property: obligation record `conservation-holds-after-every-turn`,
/// extending `owned-extents-disjoint-ledger-matches-census`.
pub(crate) const MALFORMED: &str = "a slot word is malformed";

/// Property: obligation record `conservation-holds-after-every-turn`,
/// extending `owned-extents-disjoint-ledger-matches-census`.
pub(crate) const OVERLAP: &str = "a held extent overlaps another or lies outside the volume";

/// Property: obligation record `conservation-holds-after-every-turn`,
/// extending `owned-extents-disjoint-ledger-matches-census`.
pub(crate) const FREE_RUNS: &str = "the free runs differ from the units no slot holds";

/// Property: obligation record `conservation-holds-after-every-turn`,
/// extending `owned-extents-disjoint-ledger-matches-census`.
pub(crate) const LEDGER: &str = "a ledger term differs from the slot words or the free units";

/// Property: the index direction of the obligation record
/// `conservation-holds-after-every-turn`.
pub(crate) const UNBOUND: &str = "a resident slot has no binding";

/// Property: obligation record `owner-datagram-accounts-sum-to-received`, and the receive contract of
/// [`Datagrams::receive`](super::datagram::Datagrams::receive): every lease a receive hands back is counted once in
/// its count.
pub(crate) const UNACCOUNTED: &str =
    "a datagram a link delivered to an owner has no single account";

const DUPLICATE: &str = "two bindings name one slot";

const NOT_RESIDENT: &str = "a binding names a slot holding no resident object at its incarnation";

/// Why a check did not pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// A named obligation broke.
    Violation(Obligation, &'static str),
    /// The oracle judged the recorded rows other than a pass.
    Oracle(Verdict),
    /// A report the check needs was missing, poisoned or unreadable, a bound
    /// was passed, or a required witness never armed or fired: the case
    /// cannot pass.
    Unsuccessful(&'static str),
    /// The verdict of a history a panic truncated, recorded beside the
    /// primary panic; a truncated history that passes its checks is
    /// unsuccessful.
    Truncated(Box<Failure>),
}

/// A write-once cell for a run's first failure, shared by every check.
#[derive(Debug, Clone, Default)]
pub(crate) struct FirstFailure(Rc<Mutex<Option<Failure>>>);

impl FirstFailure {
    /// Writes `failure` unless a failure is already written; returns
    /// whether it was written. A poisoned or held cell keeps what it holds.
    pub(crate) fn record(&self, failure: Failure) -> bool {
        let Ok(mut cell) = self.0.try_lock() else {
            return false;
        };
        if cell.is_some() {
            return false;
        }
        *cell = Some(failure);
        true
    }

    /// The written failure; a poisoned cell reads as what it holds, or as
    /// unsuccessful when it holds nothing, and a held cell as unsuccessful,
    /// so no unreadable cell reads as a pass.
    pub(crate) fn get(&self) -> Option<Failure> {
        match self.0.try_lock() {
            Ok(cell) => cell.clone(),
            Err(TryLockError::Poisoned(poisoned)) => Some(
                poisoned
                    .into_inner()
                    .clone()
                    .unwrap_or(Failure::Unsuccessful("the first-failure cell was poisoned")),
            ),
            Err(TryLockError::WouldBlock) => {
                Some(Failure::Unsuccessful("the first-failure cell was held"))
            }
        }
    }

    /// Poisons the cell, as a check that panicked while writing it would.
    pub(crate) fn poison(&self) {
        let cell = Rc::clone(&self.0);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _held = cell.lock();
            panic!("a check panicked while writing the first failure");
        }));
    }
}

/// Reusable copy buffers for the lenses, so a warm boundary allocates
/// nothing beyond what an earlier one reserved.
#[derive(Debug, Default)]
pub(crate) struct Lenses {
    bindings: Vec<Binding>,
    facts: Vec<SlotFact>,
    media: Vec<u8>,
    slots: Vec<u32>,
    routes: Vec<(usize, u64)>,
    holdings: Holdings,
    judgments: u64,
}

impl Lenses {
    /// Snapshots [`conserved`] and [`boundary`] judged through these
    /// buffers.
    pub(crate) fn judgments(&self) -> u64 {
        self.judgments
    }
}

/// Boundary reads require records to match `session`.
pub(crate) struct Media<'w> {
    storage: &'w Storage<TestPlatform>,
    control: SimControl,
    session: u64,
}

impl<'w> Media<'w> {
    pub(crate) fn new(
        storage: &'w Storage<TestPlatform>,
        control: SimControl,
        session: u64,
    ) -> Self {
        Self {
            storage,
            control,
            session,
        }
    }

    pub(crate) fn storage(&self) -> &'w Storage<TestPlatform> {
        self.storage
    }

    pub(crate) fn bound_record<'b>(
        &self,
        binding: Binding,
        facts: &[SlotFact],
        buffer: &'b mut Vec<u8>,
    ) -> Result<([u8; 32], u32, &'b [u8]), Failure> {
        let identity = binding.identity;
        let Some(fact) = facts
            .get(identity.slot as usize)
            .filter(|fact| fact.resident && fact.incarnation as u16 == identity.incarnation_low)
        else {
            return Err(Failure::Violation(Obligation::History, NOT_RESIDENT));
        };
        let Some(range) = fact.media() else {
            return Err(Failure::Violation(
                Obligation::Bytes,
                "a bound slot's extent lies outside the device",
            ));
        };
        if !self.control.try_device_into(range, buffer) {
            return Err(Failure::Unsuccessful("the device media was unavailable"));
        }
        let allocation = AllocationId::new(SlotIndex(identity.slot as usize), fact.incarnation);
        let Some((key, metadata, payload)) =
            self.storage
                .record_payload(buffer, allocation.record_tag(), fact, self.session)
        else {
            return Err(Failure::Violation(Obligation::Bytes, UNCHECKED_RECORD));
        };
        let Some((shard, tag, fingerprint)) = self.storage.fingerprint_of(&key) else {
            return Err(Failure::Unsuccessful("the storage was no longer live"));
        };
        if shard != binding.shard || tag != identity.tag || fingerprint != fact.fingerprint {
            return Err(Failure::Violation(
                Obligation::History,
                "a binding names a slot of another key",
            ));
        }
        Ok((key, metadata, payload))
    }
}

/// Compares every index binding of `media`'s storage, the slot it names and
/// the record that slot's extent holds on the device with `registry`, then
/// judges the storage's tables by [`conserved`]'s rule. Returns how many
/// bindings it checked.
///
/// # Errors
///
/// A registry that passed its bound or holds conflicting content, a storage
/// no longer live or an unreadable device fails as unsuccessful. Two
/// bindings naming one slot or routing one fingerprint within one shard, a binding
/// naming no resident slot at its incarnation, a slot whose key routes
/// elsewhere, or a key with no registered content fails `History`. An
/// extent outside the address space, a record whose header or chunks fail
/// their checks for the slot's allocation and `media`'s session, or a
/// payload or framing matching none of its key's content fails `Bytes`.
/// The tables' faults fail as [`conserved`] states.
pub(crate) fn boundary(
    media: &Media<'_>,
    registry: &Registry,
    lenses: &mut Lenses,
) -> Result<usize, Failure> {
    if registry.overflow {
        return Err(Failure::Unsuccessful(
            "the content registry passed its bound",
        ));
    }
    if registry.conflict {
        return Err(Failure::Unsuccessful(
            "the content registry holds two payloads for one label",
        ));
    }
    let storage = media.storage;
    let live = storage
        .bindings_into(&mut lenses.bindings)
        .and_then(|()| storage.slot_facts_into(&mut lenses.facts));
    if live.is_err() {
        return Err(Failure::Unsuccessful("the storage was no longer live"));
    }
    lenses.slots.clear();
    lenses
        .slots
        .extend(lenses.bindings.iter().map(|binding| binding.identity.slot));
    lenses.slots.sort_unstable();
    if lenses.slots.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Failure::Violation(Obligation::History, DUPLICATE));
    }
    lenses.routes.clear();
    for &binding in &lenses.bindings {
        let (key, metadata, payload) =
            media.bound_record(binding, &lenses.facts, &mut lenses.media)?;
        if !registry.knows(&key) {
            return Err(Failure::Violation(
                Obligation::History,
                "an unexpected binding",
            ));
        }
        if !registry.holds(&key, metadata, payload) {
            return Err(Failure::Violation(Obligation::Bytes, UNREGISTERED_BYTES));
        }
        let fingerprint = lenses.facts[binding.identity.slot as usize].fingerprint;
        lenses.routes.push((binding.shard, fingerprint));
    }
    lenses.routes.sort_unstable();
    if lenses.routes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Failure::Violation(
            Obligation::History,
            "two bindings route one fingerprint",
        ));
    }
    judge_tables(storage, lenses)?;
    Ok(lenses.bindings.len())
}

/// Judges `storage`'s tables and index bindings with
/// [`Holdings::judge`], from one snapshot under one quiet try of the pool
/// gate and the bindings the gate-free binding lens reads just before it,
/// into `lenses`' buffers. The two reads agree only while no controller
/// action runs between them, so the caller judges between actions.
///
/// # Errors
///
/// An unreadable snapshot fails as unsuccessful under its reason. A storage
/// past its `Live` phase, and a live storage with no index, whose bindings
/// the lens refuses, fail as unsuccessful with "the storage was no longer
/// live". A malformed slot word, an overlapping or out-of-volume extent,
/// free runs other than the unheld units, and a ledger term other than the
/// slot words or the free units fail `Resources`. A slot bound twice, a
/// binding to a slot other than a live resident at its incarnation, and an
/// unbound live resident without `ABANDONED` fail `History`.
pub(crate) fn conserved(
    storage: &Storage<TestPlatform>,
    lenses: &mut Lenses,
) -> Result<(), Failure> {
    if storage.bindings_into(&mut lenses.bindings).is_err() {
        return Err(Failure::Unsuccessful("the storage was no longer live"));
    }
    judge_tables(storage, lenses)
}

/// Judges `storage`'s tables against the bindings in `lenses`, which the
/// caller read from `storage` in the same controller action.
fn judge_tables(storage: &Storage<TestPlatform>, lenses: &mut Lenses) -> Result<(), Failure> {
    storage.holdings_into(&mut lenses.holdings);
    lenses.judgments += 1;
    lenses
        .holdings
        .judge(&lenses.bindings)
        .map_err(conservation_failure)
}

/// Judges an owner's counts against what its links delivered toward it: the leases `links` handed the owner equal
/// its `received`; for an owner whose turn never unwound, `received` equals `handled` plus `dropped`; and while it
/// also counts no datagram from no peer and no vacant slot, the truncated leases equal its truncated drops. The
/// comparison covers the leases a receive handed back; a datagram a link dropped in flight counts on neither side.
///
/// # Errors
///
/// A violation of `Contain` under [`UNACCOUNTED`] for the first comparison that fails.
pub(crate) fn accounts(
    owner: &super::OwnerReport,
    poisoned: bool,
    links: impl IntoIterator<Item = super::link::NetReport>,
) -> Result<(), Failure> {
    use super::DropReason;
    let (delivered, truncated) =
        links
            .into_iter()
            .fold((Some(0u64), Some(0u64)), |(delivered, truncated), link| {
                (
                    delivered.and_then(|sum| sum.checked_add(link.delivered)),
                    truncated.and_then(|sum| sum.checked_add(link.truncated)),
                )
            });
    let dropped = |reason: DropReason| owner.dropped_by[reason as usize];
    let unaccounted = Err(Failure::Violation(Obligation::Contain, UNACCOUNTED));
    if delivered != Some(owner.received) {
        return unaccounted;
    }
    if poisoned {
        return Ok(());
    }
    if owner.handled.checked_add(owner.dropped) != Some(owner.received) {
        return unaccounted;
    }
    let attributed = dropped(DropReason::NoPeer) == 0 && dropped(DropReason::Vacant) == 0;
    if attributed && truncated != Some(dropped(DropReason::Truncated)) {
        return unaccounted;
    }
    Ok(())
}

/// The failure [`conserved`] raises for `fault`.
pub(crate) fn conservation_failure(fault: Fault) -> Failure {
    match fault {
        Fault::Unreadable(reason) => Failure::Unsuccessful(reason),
        Fault::Malformed { .. } => Failure::Violation(Obligation::Resources, MALFORMED),
        Fault::PastVolume { .. } | Fault::Overlap { .. } => {
            Failure::Violation(Obligation::Resources, OVERLAP)
        }
        Fault::FreeRuns => Failure::Violation(Obligation::Resources, FREE_RUNS),
        Fault::SlotCounts | Fault::FreeSlots { .. } | Fault::RawFree => {
            Failure::Violation(Obligation::Resources, LEDGER)
        }
        Fault::DuplicateBinding { .. } => Failure::Violation(Obligation::History, DUPLICATE),
        Fault::NotResident { .. } => Failure::Violation(Obligation::History, NOT_RESIDENT),
        Fault::UnboundResident { .. } => Failure::Violation(Obligation::History, UNBOUND),
    }
}

/// The outcome of checking a storage snapshot against its index bindings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Tables {
    /// The tables agree with each other.
    #[default]
    Conserved,
    /// The tables disagree, by the rule's text.
    Violated(&'static str),
    /// The snapshot read nothing, for the reason given.
    Unreadable(&'static str),
}

/// The binding read and [`conservation_failure`] limit errors from
/// [`conserved`] to `Failure::Violation` and `Failure::Unsuccessful`.
pub(crate) fn tables(storage: &Storage<TestPlatform>, lenses: &mut Lenses) -> Tables {
    match conserved(storage, lenses) {
        Ok(()) => Tables::Conserved,
        Err(Failure::Violation(_, rule)) => Tables::Violated(rule),
        Err(Failure::Unsuccessful(reason)) => Tables::Unreadable(reason),
        Err(failure) => unreachable!("the conservation rule raises {failure:?}"),
    }
}

/// The recorded rows carried across stopped boundaries through the
/// oracle's continuation entry: each cut feeds the rows recorded since the
/// last one, cut after the last ordinal of the rows and of the operations
/// the caller declares pending across it.
pub(crate) struct Cuts {
    continuation: Continuation,
    fed: usize,
    owner: Owner,
    /// The verdict of the last cut.
    last: Option<Verdict>,
}

impl Cuts {
    /// Cuts of the rows of owner incarnation `owner`.
    pub(crate) fn new(owner: Owner) -> Self {
        Self {
            continuation: Continuation::new(LIMITS, Geometry::GOLDEN),
            fed: 0,
            owner,
            last: None,
        }
    }

    /// Feeds the rows of `rows` past those already fed as one segment, cut
    /// after the last ordinal of `rows` and of `pending`, with `pending` open
    /// across it, and returns the verdict so far.
    ///
    /// # Errors
    ///
    /// Unsuccessful when `rows` holds fewer rows than were already fed.
    pub(crate) fn cut(&mut self, rows: &[Row], pending: &[Pending]) -> Result<Verdict, Failure> {
        let owner = self.owner;
        self.cut_by(rows, pending, |_| owner)
    }

    /// [`cut`](Self::cut) with each fresh row's owner incarnation named by
    /// `owner`, so a history crossing a death scopes each incarnation's
    /// stops to its own custody.
    ///
    /// # Errors
    ///
    /// As [`cut`](Self::cut).
    pub(crate) fn cut_by(
        &mut self,
        rows: &[Row],
        pending: &[Pending],
        owner: impl Fn(&Row) -> Owner,
    ) -> Result<Verdict, Failure> {
        let Some(fresh) = rows.get(self.fed..) else {
            return Err(Failure::Unsuccessful("the row log shrank across a cut"));
        };
        let end = rows
            .iter()
            .flat_map(Row::ordinals)
            .map(|(_, at)| at.0)
            .chain(pending.iter().map(|open| open.invoked.0))
            .max()
            .unwrap_or(0);
        let entries: Vec<Entry> = fresh
            .iter()
            .map(|row| Entry::new(row.clone(), WideOp(u64::from(row.op.0)), owner(row)))
            .collect();
        self.fed = rows.len();
        self.continuation
            .segment(entries, Ordinal(end + 1), pending);
        let verdict = self.continuation.judge();
        self.last = Some(verdict);
        Ok(verdict)
    }

    /// Whether the last cut's verdict passed; it covers the rows fed so far.
    pub(crate) fn passed(&self) -> bool {
        matches!(self.last, Some(Verdict::Pass(_)))
    }

    /// The verdict over every row fed.
    pub(crate) fn finish(&self) -> Verdict {
        self.continuation.finish()
    }

    /// Searched operations collapsed into frontiers so far, and the most
    /// states one frontier holds.
    pub(crate) fn collapsed(&self) -> (usize, usize) {
        self.continuation.collapsed()
    }
}

/// Required witnesses, their required ingredients and what fired, every log
/// bounded by one limit.
#[derive(Debug, Default)]
pub(crate) struct Witnesses {
    required: Vec<(&'static str, &'static [&'static str])>,
    active: Vec<&'static str>,
    ingredients: Vec<Ingredient>,
    fired: Vec<&'static str>,
    limit: usize,
    overflow: bool,
    /// A capture some witness needed was dropped at its bound.
    dropped: bool,
}

/// One ingredient a correlation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ingredient {
    witness: &'static str,
    correlation: u64,
    name: &'static str,
}

/// Pushes `item` onto `log` unless `log` holds `limit` items, which sets
/// `overflow`.
fn bounded<T>(log: &mut Vec<T>, item: T, limit: usize, overflow: &mut bool) {
    if log.len() == limit {
        *overflow = true;
    } else {
        log.push(item);
    }
}

impl Witnesses {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Requires `witness` of the case, firing only on every one of `needs`.
    pub(crate) fn require(&mut self, witness: &'static str, needs: &'static [&'static str]) {
        bounded(
            &mut self.required,
            (witness, needs),
            self.limit,
            &mut self.overflow,
        );
    }

    /// Marks `witness` active: its scenario armed it.
    pub(crate) fn activate(&mut self, witness: &'static str) {
        bounded(&mut self.active, witness, self.limit, &mut self.overflow);
    }

    /// Records ingredient `name` of `witness` for `correlation`, such as one
    /// request or one attempt.
    pub(crate) fn ingredient(
        &mut self,
        witness: &'static str,
        correlation: u64,
        name: &'static str,
    ) {
        let ingredient = Ingredient {
            witness,
            correlation,
            name,
        };
        bounded(
            &mut self.ingredients,
            ingredient,
            self.limit,
            &mut self.overflow,
        );
    }

    /// Fires `witness` for `correlation` when it is armed and every
    /// ingredient it requires was set for that correlation; returns whether
    /// it fired. A witness with no requirement never fires.
    pub(crate) fn fire(&mut self, witness: &'static str, correlation: u64) -> bool {
        let Some(&(_, needs)) = self.required.iter().find(|(name, _)| *name == witness) else {
            return false;
        };
        let correlated = !needs.is_empty()
            && self.active.contains(&witness)
            && needs.iter().all(|need| {
                self.ingredients.contains(&Ingredient {
                    witness,
                    correlation,
                    name: need,
                })
            });
        if correlated {
            bounded(&mut self.fired, witness, self.limit, &mut self.overflow);
        }
        correlated
    }

    /// Entries the longest of the requirement, activation, ingredient and
    /// fired logs holds; the limit bounds each.
    pub(crate) fn logged(&self) -> usize {
        [
            self.required.len(),
            self.active.len(),
            self.ingredients.len(),
            self.fired.len(),
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
    }

    /// Records a link's verdict over the captures a witness reads: one that
    /// is not a pass dropped or spoiled a capture.
    pub(crate) fn captures(&mut self, verdict: &super::audit::Verdict) {
        self.dropped |= *verdict != super::audit::Verdict::Pass;
    }

    /// Passes when every required witness was armed and fired; an inactive
    /// or unfired witness, an overflowed log or a dropped capture is
    /// unsuccessful.
    pub(crate) fn verdict(&self) -> Result<(), Failure> {
        if self.overflow {
            return Err(Failure::Unsuccessful("the witness log passed its bound"));
        }
        if self.dropped {
            return Err(Failure::Unsuccessful(
                "a capture a witness needs was dropped",
            ));
        }
        for (witness, _) in &self.required {
            if !self.active.contains(witness) {
                return Err(Failure::Unsuccessful("a required witness was never armed"));
            }
            if !self.fired.contains(witness) {
                return Err(Failure::Unsuccessful("a required witness never fired"));
            }
        }
        Ok(())
    }
}

/// What an observer reads at teardown: the storage, the device, the
/// registry, the rows recorded so far and the case's witnesses.
pub(crate) struct Observer<'w> {
    media: Media<'w>,
    registry: Rc<RefCell<Registry>>,
    rows: Rc<RefCell<Vec<Row>>>,
    witnesses: Option<Rc<RefCell<Witnesses>>>,
    first: FirstFailure,
    /// Whether a failure raises when the observer drops on normal return.
    raises: bool,
}

impl<'w> Observer<'w> {
    pub(crate) fn new(
        media: Media<'w>,
        registry: Rc<RefCell<Registry>>,
        rows: Rc<RefCell<Vec<Row>>>,
        first: FirstFailure,
    ) -> Self {
        Self {
            media,
            registry,
            rows,
            witnesses: None,
            first,
            raises: true,
        }
    }

    /// Judges `witnesses` at teardown too.
    pub(crate) fn witnessing(mut self, witnesses: Rc<RefCell<Witnesses>>) -> Self {
        self.witnesses = Some(witnesses);
        self
    }

    /// Sets `media` as the media the observer judges at teardown, as a
    /// relaunched owner's storage replaces its predecessor's.
    pub(crate) fn follow(&mut self, media: Media<'w>) {
        self.media = media;
    }

    /// Records a failure at drop without raising it, for a test that reads
    /// the first-failure cell afterwards.
    pub(crate) fn quiet(mut self) -> Self {
        self.raises = false;
        self
    }

    /// The world's judgment now, read passively: the boundary check, the
    /// witnesses, then the oracle over the rows; a borrowed registry,
    /// witness log or row log is a missing report.
    fn judge(&self) -> Result<(), Failure> {
        let Ok(registry) = self.registry.try_borrow() else {
            return Err(Failure::Unsuccessful(
                "the registry was borrowed at teardown",
            ));
        };
        boundary(&self.media, &registry, &mut Lenses::default())?;
        if let Some(witnesses) = &self.witnesses {
            let Ok(witnesses) = witnesses.try_borrow() else {
                return Err(Failure::Unsuccessful(
                    "the witness log was borrowed at teardown",
                ));
            };
            witnesses.verdict()?;
        }
        let Ok(rows) = self.rows.try_borrow() else {
            return Err(Failure::Unsuccessful(
                "the row log was borrowed at teardown",
            ));
        };
        if rows.is_empty() {
            return Ok(());
        }
        match crate::oracle::check(&crate::oracle::Recorder::rebuilt(rows.iter().cloned())) {
            Verdict::Pass(_) => Ok(()),
            verdict => Err(Failure::Oracle(verdict)),
        }
    }
}

thread_local! {
    /// Teardown judgments [`Observer`] drops recorded on this thread.
    static TEARDOWNS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Teardown judgments [`Observer`] drops ran on this thread, those of a
/// panicking run included, each counted once its judgment or a panic's
/// truncation has run.
pub(crate) fn teardowns() -> u64 {
    TEARDOWNS.with(std::cell::Cell::get)
}

impl Drop for Observer<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // A second panic here would abort the process, so the checker runs caught.
            let judged = catch_unwind(AssertUnwindSafe(|| self.judge())).unwrap_or(Err(
                Failure::Unsuccessful("the checker panicked while unwinding"),
            ));
            let truncated = judged.err().unwrap_or(Failure::Unsuccessful(
                "a panic truncated the run before teardown",
            ));
            self.first.record(Failure::Truncated(Box::new(truncated)));
            TEARDOWNS.with(|count| count.set(count.get() + 1));
            return;
        }
        if let Err(failure) = self.judge() {
            self.first.record(failure);
        }
        TEARDOWNS.with(|count| count.set(count.get() + 1));
        if self.raises
            && let Some(failure) = self.first.get()
        {
            panic!("the world failed at teardown: {failure:?}");
        }
    }
}
