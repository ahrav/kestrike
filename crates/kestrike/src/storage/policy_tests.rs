//! Policy domain membership across the storage lifecycle: every domain's list
//! equals an independent oracle's resident-and-unobserved set, in insertion
//! order, after every event of seeded histories; each exit site detaches or
//! clears exactly once and repairs the hand; the tables are charged once.
//!
//! The oracle keeps the slots `bind` made resident, newest first, and
//! removes a slot at the event that first observes its exit: `abandon` with
//! the gate free, the extent's return, or the service call that sights a
//! retirement parked while the gate was held. Its detached set holds the
//! slots removed by observation whose extents have not returned.
//!
//! An event ledger, built from the generated events alone, decides which
//! slots each event returns; production's free states are compared with it.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::Ordering;

use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::gate::GateError;
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::policy::{
    Domain, Node, POLICY_NONE, PolicySlot, Queue, check_domain, check_in_flight_units,
};
use super::probe::{self, Event};
use super::release::ServiceError;
use super::slot::Record;
use super::tables::{SlotIndex, SlotState};
use super::test_platform::{Op, TestPlatform, finalize};
use super::word::{ABANDONED, DETACHED, EVICTED, LINKED, RETIRED, VISITED};
use super::{Completed, ExtentLease, Finalization, Resident, RetireOutcome};

const PAGE: usize = 4096;
const SLOTS: usize = 24;

fn config(slot_count: usize) -> StorageConfig {
    StorageConfig {
        page_size: PAGE,
        engine_budget: 1 << 24,
        body_cap: 200,
        metadata_cap: Some(16),
        lease_limit: 64,
        object_rights: 8,
        reader_limit: 4,
        volume: crate::storage::test_volume((slot_count + 1) * crate::storage::IO_UNIT, slot_count),
    }
}

fn storage_with(slots: usize) -> Storage<TestPlatform> {
    let placement = PlacementConfig { control_home: 0 };
    Storage::initialize(
        &config(slots).validate().unwrap(),
        &placement,
        TestPlatform::heap(PAGE),
    )
    .unwrap()
}

fn budget() -> WorkBudget {
    WorkBudget::new(1 << 10)
}

/// A completed object of a `body`-byte body, made resident by `bind`.
fn completed(storage: &Storage<TestPlatform>, body: usize) -> Completed<'_, TestPlatform> {
    storage
        .reserve(Some(1), Some(body), &mut budget())
        .unwrap()
        .complete([body as u8; 32], u64::MAX, &mut budget())
        .ok()
        .unwrap()
}

fn service(storage: &Storage<TestPlatform>) -> super::release::ServiceReport {
    storage.service(&mut WorkBudget::new(1000)).unwrap()
}

/// Requests certification and asserts the certificate is current within
/// its budget.
fn certify(storage: &Storage<TestPlatform>) {
    let report = storage.certify(&mut WorkBudget::new(1000)).unwrap();
    assert!(report.certified.is_some() && !report.budget_exhausted);
}

/// The domain's members head to tail, every slot's links and policy bits
/// and the detached count, read under the gate, after the structural check.
fn snapshot(storage: &Storage<TestPlatform>) -> (Vec<usize>, Vec<Node>, u32) {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let nodes = tables.queue().nodes();
    let d = *tables.domain;
    let in_domain = |slot: usize| {
        matches!(
            live.gate_state(slot).0,
            SlotState::Resident | SlotState::Retired
        )
    };
    check_domain(&nodes, &d, in_domain);
    check_in_flight_units(&nodes, &d, in_domain, |slot| {
        u64::from(tables.held_units(slot))
    });
    let detached = d.detached;
    (tables.queue().members(), nodes, detached)
}

/// The independent membership model.
#[derive(Default)]
struct Oracle {
    /// Resident and unobserved slots, newest first.
    list: Vec<usize>,
    /// Slots whose retirement was observed and whose extent has not
    /// returned.
    detached: BTreeSet<usize>,
    /// Slots whose retirement was parked while the gate was held and that
    /// no service call has sighted yet.
    parked: Vec<usize>,
}

impl Oracle {
    fn bind(&mut self, slot: usize) {
        assert!(!self.list.contains(&slot));
        self.list.insert(0, slot);
    }

    fn remove(&mut self, slot: usize) {
        let at = self.list.iter().position(|&s| s == slot).unwrap();
        self.list.remove(at);
    }

    /// `abandon` or service observed the retirement of a member.
    fn observe(&mut self, slot: usize) {
        self.remove(slot);
        assert!(self.detached.insert(slot));
    }

    /// The extent of `slot` returned.
    fn returned(&mut self, slot: usize) {
        if !self.detached.remove(&slot) && self.list.contains(&slot) {
            self.remove(slot);
        }
    }

    /// Compares the oracle with the tables: the list in order, the detached
    /// count, and every non-member carrying exactly its detached bit.
    fn compare(&self, storage: &Storage<TestPlatform>) -> Result<(), String> {
        let (list, nodes, detached) = snapshot(storage);
        if list != self.list {
            return Err(format!("tables {list:?}, oracle {:?}", self.list));
        }
        if detached as usize != self.detached.len() {
            return Err(format!("detached {detached}"));
        }
        for &slot in &self.detached {
            if nodes[slot].state != DETACHED {
                return Err(format!("slot {slot} not detached"));
            }
        }
        for (slot, node) in nodes.iter().enumerate() {
            let known = self.list.contains(&slot) || self.detached.contains(&slot);
            if !known && *node != Node::CLEAR {
                return Err(format!("slot {slot} not clear: {node:?}"));
            }
        }
        Ok(())
    }
}

/// How an owner's hold ended: by a release or a drop of an owner never
/// handed off, or by an anchored retirement, whose anchor a later
/// certificate must cover before it releases and the slot returns.
#[derive(Clone, Copy, PartialEq)]
enum End {
    Unanchored,
    Anchored,
}

/// The comparison point after an event: what the event let production
/// return.
#[derive(Clone, Copy, PartialEq)]
enum Boundary {
    /// An event that takes no service opportunity; nothing returns.
    Hold,
    /// A service call refused for its budget or a busy gate.
    Refused,
    /// The gate-free return of `slot`'s released owner.
    Immediate(usize),
    /// A fully funded service call.
    Funded,
}

/// The return ledger, derived from the generated events alone: per bound
/// slot its incarnation, how and when the owner's hold ended, and the
/// rights still outstanding; and the end clock the last certification
/// covered. A slot is eligible to return once its owner's hold has ended
/// and no right remains. An eligible slot returns at the gate-free return
/// of its released owner, or at a funded service call; an anchored slot
/// also needs a certification after its retirement.
#[derive(Default)]
struct Ledger {
    bound: BTreeMap<usize, u32>,
    ended: BTreeMap<usize, (u64, End)>,
    rights: BTreeMap<usize, usize>,
    clock: u64,
    certified: u64,
    /// Eligible slots found allocated after a refused service call.
    awaited_funding: usize,
    /// Eligible anchored slots found allocated after a funded call that no
    /// certification since their retirement covered.
    awaited_certificate: usize,
}

impl Ledger {
    fn bind(&mut self, slot: usize, incarnation: u32) {
        if let Some(held) = self.bound.insert(slot, incarnation) {
            panic!(
                "slot {slot} incarnation {incarnation} bound while incarnation {held} holds it: a premature return"
            );
        }
    }

    fn end(&mut self, slot: usize, how: End) {
        self.clock += 1;
        assert!(
            self.ended.insert(slot, (self.clock, how)).is_none(),
            "slot {slot}'s owner hold ended twice"
        );
    }

    fn certify(&mut self) {
        self.certified = self.clock;
    }

    fn grant(&mut self, slot: usize) {
        *self.rights.entry(slot).or_default() += 1;
    }

    fn release(&mut self, slot: usize) {
        let rights = self
            .rights
            .get_mut(&slot)
            .expect("a right the ledger granted");
        *rights -= 1;
        if *rights == 0 {
            self.rights.remove(&slot);
        }
    }

    /// Whether `slot`'s owner hold has ended and no right remains.
    fn eligible(&self, slot: usize) -> bool {
        self.ended.contains_key(&slot) && !self.rights.contains_key(&slot)
    }

    /// Compares the ledger with every bound slot's production state after
    /// an event that reached `boundary`, and returns the slots the event
    /// returned, in slot order. A returned slot leaves the ledger, so a
    /// later bind of it names a fresh incarnation.
    ///
    /// # Errors
    ///
    /// - If a bound slot shows an incarnation other than its bound one.
    /// - If a slot the event returns is still allocated.
    /// - If a slot is free while its owner's hold or a right remains.
    /// - If an eligible slot is free at a boundary that returns it neither
    ///   by its own gate-free return nor by a funded, covering call.
    fn check(
        &mut self,
        storage: &Storage<TestPlatform>,
        boundary: Boundary,
    ) -> Result<Vec<usize>, String> {
        let mut returned = Vec::new();
        for (&slot, &incarnation) in &self.bound {
            let (state, current) = storage.slot_state(SlotIndex(slot)).unwrap();
            if current != incarnation {
                return Err(format!(
                    "slot {slot} bound to incarnation {incarnation} shows {current}"
                ));
            }
            let free = state == SlotState::Free;
            let certified = match self.ended.get(&slot) {
                Some(&(at, End::Anchored)) => at <= self.certified,
                _ => true,
            };
            let eligible = self.eligible(slot);
            let returns = eligible
                && match boundary {
                    Boundary::Hold | Boundary::Refused => false,
                    Boundary::Immediate(released) => released == slot,
                    Boundary::Funded => certified,
                };
            match (eligible, returns, free) {
                (_, true, true) => returned.push(slot),
                (_, true, false) => {
                    return Err(format!(
                        "slot {slot} incarnation {incarnation} eligible and not returned"
                    ));
                }
                (false, _, true) => {
                    return Err(format!(
                        "slot {slot} incarnation {incarnation} returned while a hold remains"
                    ));
                }
                (true, false, true) => {
                    return Err(format!(
                        "slot {slot} incarnation {incarnation} returned without a funded visit or certificate"
                    ));
                }
                (true, false, false) => match boundary {
                    Boundary::Refused => self.awaited_funding += 1,
                    Boundary::Funded => self.awaited_certificate += 1,
                    _ => {}
                },
                (false, false, false) => {}
            }
        }
        for slot in &returned {
            self.bound.remove(slot);
            self.ended.remove(slot);
        }
        Ok(returned)
    }
}

/// What a history holds between events.
enum Held<'s> {
    Completed(Completed<'s, TestPlatform>),
    /// A resident object and its lease, or its anchor alone once the lease
    /// has gone first.
    Anchored(
        Resident<'s, TestPlatform>,
        Option<ExtentLease<'s, TestPlatform>>,
    ),
    /// A lease outstanding beside its object's anchor or after the object's
    /// retirement.
    Lease(ExtentLease<'s, TestPlatform>),
}

/// Seeded histories over bind, handoff, a retain, a lease dropped before
/// or after its anchor's retirement, retirement with the gate free and
/// held, owner drop and return with the gate free and held, certification,
/// service funded, refused or uncertified, and a stale park against a
/// reused slot:
/// after every event the domain's list equals the oracle's, and the event
/// ledger's returns equal production's free states. A planted retired slot
/// still linked fails the comparison.
#[test]
fn membership_equals_the_unobserved_residents_after_every_event() {
    for seed in [0x9E37_79B9u32, 0x85EB_CA6B, 0xC2B2_AE35, 0x27D4_EB2F] {
        let storage = storage_with(SLOTS);
        let mut seed = seed;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as usize
        };
        let mut oracle = Oracle::default();
        let mut ledger = Ledger::default();
        // Slots retired with the anchor as their only hold, or with a right
        // still out at retirement; reused slots with their prior incarnation.
        let (mut anchor_last, mut reader_last) = (BTreeSet::new(), BTreeSet::new());
        let mut stale_targets: Vec<(usize, u32)> = Vec::new();
        let mut parked_returned = 0usize;
        let mut detached_returned = 0usize;
        let (mut returned_anchor_last, mut returned_reader_last) = (0usize, 0usize);
        let mut stale_parks = 0usize;
        let mut retains = 0usize;
        let mut serviced: Vec<usize> = Vec::new();
        let mut held: Vec<(usize, Held<'_>)> = Vec::new();
        let mut sighted_held = 0usize;
        let mut full = 0usize;
        let mut ever_bound = BTreeMap::new();
        for _ in 0..600 {
            let busy = next() % 4 == 0;
            let mut boundary = Boundary::Hold;
            match next() % 10 {
                0..=2 => {
                    let body = if next() % 2 == 0 { 8 } else { 100 };
                    let Ok(allocation) = storage.reserve(Some(1), Some(body), &mut budget()) else {
                        full += 1;
                        continue;
                    };
                    let object = allocation
                        .complete([body as u8; 32], u64::MAX, &mut budget())
                        .ok()
                        .unwrap();
                    let slot = object.id().slot_index();
                    let incarnation = object.id().incarnation();
                    if let Some(prior) = ever_bound.insert(slot, incarnation) {
                        stale_targets.push((slot, prior));
                    }
                    ledger.bind(slot, incarnation);
                    oracle.bind(slot);
                    held.push((slot, Held::Completed(object)));
                }
                3 if !held.is_empty() => {
                    let at = next() % held.len();
                    match held.swap_remove(at) {
                        (slot, Held::Completed(object)) => {
                            let (resident, lease) = object.handoff(&mut budget()).ok().unwrap();
                            ledger.grant(slot);
                            held.push((slot, Held::Anchored(resident, Some(lease))));
                        }
                        (slot, Held::Anchored(resident, Some(lease))) if next() % 2 == 0 => {
                            drop(lease);
                            ledger.release(slot);
                            held.push((slot, Held::Anchored(resident, None)));
                        }
                        // A retain: a further right on a resident object,
                        // within the object's and the storage's limits.
                        (slot, Held::Anchored(resident, Some(lease)))
                            if ledger.rights[&slot] < 4
                                && ledger.rights.values().sum::<usize>() < 32 =>
                        {
                            let retained = lease.duplicate();
                            ledger.grant(slot);
                            retains += 1;
                            held.push((slot, Held::Lease(retained)));
                            held.push((slot, Held::Anchored(resident, Some(lease))));
                        }
                        other => held.push(other),
                    }
                }
                4 | 5 if !held.is_empty() => {
                    let at = next() % held.len();
                    let (slot, object) = held.swap_remove(at);
                    let live = storage.live_pool().unwrap();
                    let gate = busy.then(|| live.lock().unwrap());
                    match object {
                        Held::Completed(object) => {
                            ledger.end(slot, End::Unanchored);
                            if next() % 2 == 0 {
                                let transfer = object.release();
                                let returned = storage.return_allocation(transfer, &mut budget());
                                drop(gate);
                                if busy {
                                    oracle.parked.push(slot);
                                } else {
                                    assert_eq!(
                                        returned,
                                        Ok(super::release::ReturnOutcome::Returned)
                                    );
                                    boundary = Boundary::Immediate(slot);
                                }
                            } else {
                                drop(object);
                                drop(gate);
                                if busy {
                                    oracle.parked.push(slot);
                                } else {
                                    oracle.observe(slot);
                                }
                            }
                        }
                        Held::Anchored(resident, lease) => {
                            ledger.end(slot, End::Anchored);
                            if ledger.rights.contains_key(&slot) {
                                reader_last.insert(slot);
                            } else {
                                anchor_last.insert(slot);
                            }
                            let outcome = resident.retire();
                            drop(gate);
                            if busy {
                                assert_eq!(outcome, RetireOutcome::Parked);
                                oracle.parked.push(slot);
                            } else {
                                assert_eq!(outcome, RetireOutcome::Recorded);
                                oracle.observe(slot);
                            }
                            if let Some(lease) = lease {
                                held.push((slot, Held::Lease(lease)));
                            }
                        }
                        Held::Lease(lease) => {
                            drop(lease);
                            ledger.release(slot);
                        }
                    }
                }
                6 if !stale_targets.is_empty() => {
                    // A park naming a reused slot's prior incarnation
                    // changes nothing the successor holds.
                    let (slot, prior) = stale_targets.swap_remove(next() % stale_targets.len());
                    let live = storage.live_pool().unwrap();
                    let before = live.word(slot);
                    super::release::park(live, slot, prior);
                    assert_eq!(live.word(slot), before);
                    // A successor bound and not yet abandoned shows the
                    // incarnation check alone refused the park.
                    stale_parks += usize::from(
                        before & ABANDONED == 0
                            && ledger.bound.get(&slot).is_some_and(|&bound| bound != prior),
                    );
                }
                7 if next() % 2 == 0 => {
                    // A service opportunity refused for its budget or a busy
                    // gate returns nothing and sights nothing.
                    if busy {
                        let live = storage.live_pool().unwrap();
                        let _gate = live.lock().unwrap();
                        assert_eq!(
                            storage.service(&mut budget()),
                            Err(ServiceError::Gate(GateError::Contended))
                        );
                    } else {
                        let mut short = WorkBudget::new(storage.service_minimum() - 1);
                        assert_eq!(
                            storage.service(&mut short),
                            Err(ServiceError::BudgetExhausted)
                        );
                    }
                    boundary = Boundary::Refused;
                }
                _ => {
                    // Service, after a certification in most calls.
                    if next() % 3 != 0 {
                        certify(&storage);
                        ledger.certify();
                    }
                    probe::arm();
                    let report = service(&storage);
                    let log = probe::events();
                    probe::disarm();
                    assert!(!report.budget_exhausted && report.partial == 0 && !log.overflowed);
                    sighted_held += report.held;
                    serviced = log
                        .events
                        .iter()
                        .filter_map(|event| match *event {
                            Event::Return { slot } => Some(slot),
                            _ => None,
                        })
                        .collect();
                    serviced.sort_unstable();
                    boundary = Boundary::Funded;
                }
            }
            // The ledger alone decides what the event returned; production's
            // free states serve only as the comparison.
            let returned = ledger.check(&storage, boundary).unwrap();
            if boundary == Boundary::Funded {
                // The call returned each slot the ledger returns once, and
                // no other.
                assert_eq!(std::mem::take(&mut serviced), returned);
                // Every parked obligation is sighted: returned when the
                // ledger returns it, detached otherwise.
                for slot in std::mem::take(&mut oracle.parked) {
                    if returned.contains(&slot) {
                        parked_returned += 1;
                    } else {
                        oracle.observe(slot);
                    }
                }
            }
            for slot in returned {
                detached_returned += usize::from(oracle.detached.contains(&slot));
                returned_anchor_last += usize::from(anchor_last.remove(&slot));
                returned_reader_last += usize::from(reader_last.remove(&slot));
                oracle.returned(slot);
            }
            oracle.compare(&storage).unwrap();
        }
        assert!(
            stale_parks > 0,
            "the history never parked a reused slot's prior incarnation"
        );
        assert!(
            parked_returned > 0,
            "the history never returned a parked slot"
        );
        assert!(
            detached_returned > 0,
            "the history never returned a detached slot"
        );
        assert!(
            returned_anchor_last > 0,
            "the history never returned a slot its anchor held last"
        );
        assert!(retains > 0, "the history never retained a further right");
        assert!(
            returned_reader_last > 0,
            "the history never returned a slot retired under an outstanding right"
        );
        assert!(
            ledger.awaited_funding > 0,
            "no refused call met an eligible slot"
        );
        assert!(
            ledger.awaited_certificate > 0,
            "no funded call met an eligible slot awaiting its certificate"
        );
        assert!(sighted_held > 0, "the history never sighted a held slot");
        assert!(full > 0, "the history never filled the volume");

        // Negative control: a retired slot still linked is caught.
        let slot = *oracle
            .detached
            .first()
            .expect("the history ended with nothing detached");
        {
            let live = storage.live_pool().unwrap();
            let mut access = live.lock().unwrap();
            let mut tables = access.tables();
            live.records()[slot].clear_bits(DETACHED);
            tables.domain.detached -= 1;
            tables.queue().link(slot);
        }
        assert!(oracle.compare(&storage).is_err());
        // The planted link would trip the return path's structural
        // assertions, so the owners are not dropped.
        std::mem::forget(held);
    }
}

/// A retired slot whose lease is still out, its stamp certified, and the
/// lease's right as the event ledger counts it.
fn retired_under_a_lease(
    storage: &Storage<TestPlatform>,
) -> (Ledger, usize, ExtentLease<'_, TestPlatform>) {
    let mut ledger = Ledger::default();
    let object = completed(storage, 8);
    let slot = object.id().slot_index();
    ledger.bind(slot, object.id().incarnation());
    let (resident, lease) = object.handoff(&mut budget()).ok().unwrap();
    ledger.grant(slot);
    ledger.end(slot, End::Anchored);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    certify(storage);
    ledger.certify();
    service(storage);
    assert_eq!(ledger.check(storage, Boundary::Funded), Ok(Vec::new()));
    (ledger, slot, lease)
}

/// A planted premature return: production frees a retired slot whose lease
/// is still out, after a phantom release of that lease's right, and the
/// event ledger, which still counts the right, refuses the free state.
#[test]
fn a_premature_return_disagrees_with_the_event_ledger() {
    let storage = storage_with(SLOTS);
    let (mut ledger, slot, lease) = retired_under_a_lease(&storage);
    // The plant: the lease's right leaves the count while the lease lives.
    storage.live_pool().unwrap().records()[slot]
        .ident
        .fetch_sub(super::word::REF, Ordering::Release);
    certify(&storage);
    service(&storage);
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
    let refused = ledger.check(&storage, Boundary::Funded).unwrap_err();
    assert!(
        refused.contains("returned while a hold remains"),
        "{refused}"
    );
    // The lease's right is already gone from the word.
    std::mem::forget(lease);
}

/// A planted withheld return: a phantom right keeps a slot allocated after
/// its last lease drops, and the event ledger, which counts no right left,
/// refuses the allocated state after a funded, certified call.
#[test]
fn a_withheld_return_disagrees_with_the_event_ledger() {
    let storage = storage_with(SLOTS);
    let (mut ledger, slot, lease) = retired_under_a_lease(&storage);
    // The plant: a right the ledger never granted.
    storage.live_pool().unwrap().records()[slot]
        .ident
        .fetch_add(super::word::REF, Ordering::Release);
    drop(lease);
    ledger.release(slot);
    certify(&storage);
    ledger.certify();
    service(&storage);
    assert_ne!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
    let refused = ledger.check(&storage, Boundary::Funded).unwrap_err();
    assert!(refused.contains("eligible and not returned"), "{refused}");
}

/// The domain's hand, read under the gate.
fn hand(storage: &Storage<TestPlatform>) -> u32 {
    let live = storage.live_pool().unwrap();
    live.lock().unwrap().tables().domain.hand
}

fn set_hand(storage: &Storage<TestPlatform>, slot: usize) {
    let live = storage.live_pool().unwrap();
    live.lock().unwrap().tables().domain.hand = slot as u32;
}

/// A parked retirement on a leased member is detached, once, in the service
/// call that sights it: `Parked` at the park, `Sighted` at every sighting
/// while the lease holds it, `Detached` only at the first. The later return
/// clears the slot's policy bits and the count. A retirement recorded with
/// the gate free detaches in `abandon`'s hold, and service's later sighting
/// of the retired record detaches nothing again.
#[test]
fn a_parked_retirement_detaches_once_in_the_sighting_service_call() {
    let storage = storage_with(4);
    let (resident, lease) = completed(&storage, 100)
        .handoff(&mut budget())
        .ok()
        .unwrap();
    let slot = resident.id().slot_index();
    let live = storage.live_pool().unwrap();
    probe::arm();
    let gate = live.lock().unwrap();
    assert_eq!(resident.retire(), RetireOutcome::Parked);
    drop(gate);
    assert_eq!(probe::events().events, [Event::Parked { slot }]);
    assert_eq!(snapshot(&storage).0, [slot], "a parked member stays linked");

    probe::arm();
    certify(&storage);
    assert_eq!(service(&storage).held, 1);
    let policy = |log: Vec<Event>| -> Vec<Event> {
        log.into_iter()
            .filter(|e| matches!(e, Event::Detached { .. } | Event::Sighted { .. }))
            .collect()
    };
    assert_eq!(
        policy(probe::events().events),
        [Event::Sighted { slot }, Event::Detached { slot }]
    );
    let (list, nodes, detached) = snapshot(&storage);
    assert!(list.is_empty());
    assert_eq!((nodes[slot].state, detached), (DETACHED, 1));

    // The lease still holds it: sighted again, detached no more.
    probe::arm();
    certify(&storage);
    assert_eq!(service(&storage).held, 1);
    assert_eq!(policy(probe::events().events), [Event::Sighted { slot }]);
    assert_eq!(snapshot(&storage).2, 1);

    drop(lease);
    certify(&storage);
    assert_eq!(service(&storage).serviced, 1);
    let (_, nodes, detached) = snapshot(&storage);
    assert_eq!((nodes[slot], detached), (Node::CLEAR, 0));

    // A retirement recorded under a free gate detaches once; the held
    // passes that follow find the retired bit and neither sight nor detach.
    let (resident, lease) = completed(&storage, 100)
        .handoff(&mut budget())
        .ok()
        .unwrap();
    let slot = resident.id().slot_index();
    probe::arm();
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(probe::events().events, [Event::Detached { slot }]);
    assert_ne!(
        live.flags(slot) & RETIRED,
        0,
        "the held passes below take the retired branch"
    );
    for _ in 0..2 {
        probe::arm();
        certify(&storage);
        assert_eq!(service(&storage).held, 1);
        assert_eq!(policy(probe::events().events), []);
        let (list, nodes, detached) = snapshot(&storage);
        assert!(list.is_empty());
        assert_eq!((nodes[slot].state, detached), (DETACHED, 1));
    }
    drop(lease);
    certify(&storage);
    assert_eq!(service(&storage).serviced, 1);
    let (_, nodes, detached) = snapshot(&storage);
    assert_eq!((nodes[slot], detached), (Node::CLEAR, 0));
    probe::disarm();
}

/// A park by a stale transfer names an earlier incarnation: it changes no
/// bit of the word, so service finds nothing and never unlinks the slot's
/// current occupant.
#[test]
fn a_stale_park_never_unlinks_the_current_occupant() {
    let storage = storage_with(1);
    let first = completed(&storage, 8);
    let stale = first.id();
    let transfer = first.release();
    assert_eq!(
        storage.return_allocation(transfer, &mut budget()),
        Ok(super::release::ReturnOutcome::Returned)
    );
    let current = completed(&storage, 8);
    assert_eq!(current.id().slot_index(), stale.slot_index());
    let live = storage.live_pool().unwrap();
    let before = live.word(stale.slot_index());
    super::release::park(live, stale.slot_index(), stale.incarnation());
    assert_eq!(live.word(stale.slot_index()), before);
    let report = service(&storage);
    assert_eq!((report.held, report.serviced), (0, 0));
    let (list, nodes, detached) = snapshot(&storage);
    assert_eq!(list, [stale.slot_index()]);
    assert_eq!((nodes[stale.slot_index()].state, detached), (LINKED, 0));
    drop(current);
}

/// Unlinking the hand's slot at each exit site leaves the hand on its
/// head-side neighbour: abandon with the gate, service's sighting, the
/// direct return and service's return of a parked obligation. From the head
/// the hand becomes none.
#[test]
fn every_exit_site_repairs_the_hand() {
    let storage = storage_with(8);
    let objects: Vec<_> = (0..3).map(|_| completed(&storage, 8)).collect();
    let slots: Vec<usize> = objects.iter().map(|o| o.id().slot_index()).collect();
    // Head to tail: slots[2], slots[1], slots[0].
    let mut objects = objects.into_iter();
    let (tail, middle, head) = (
        objects.next().unwrap(),
        objects.next().unwrap(),
        objects.next().unwrap(),
    );

    // Abandon: the tail leaves; the hand moves to the middle.
    set_hand(&storage, slots[0]);
    drop(tail);
    assert_eq!(hand(&storage), slots[1] as u32);

    // Direct return of the middle: the hand moves to the head.
    let transfer = middle.release();
    storage.return_allocation(transfer, &mut budget()).unwrap();
    assert_eq!(hand(&storage), slots[2] as u32);

    // Parked return of the head, serviced: the hand becomes none.
    let live = storage.live_pool().unwrap();
    let gate = live.lock().unwrap();
    let transfer = head.release();
    storage.return_allocation(transfer, &mut budget()).unwrap();
    drop(gate);
    service(&storage);
    assert_eq!(hand(&storage), POLICY_NONE);

    // Service's sighting of a parked retirement held by a lease.
    let (a, lease_a) = completed(&storage, 8).handoff(&mut budget()).ok().unwrap();
    let b = completed(&storage, 8);
    set_hand(&storage, a.id().slot_index());
    let gate = live.lock().unwrap();
    let a_slot = a.id().slot_index();
    assert_eq!(a.retire(), RetireOutcome::Parked);
    drop(gate);
    assert_eq!(hand(&storage), a_slot as u32);
    certify(&storage);
    service(&storage);
    assert_eq!(hand(&storage), b.id().slot_index() as u32);
    snapshot(&storage);
    drop((lease_a, b));
}

/// A reused slot links once with clear links, clear policy bits and a clear
/// visited bit; a slot whose incarnation is exhausted is quarantined at its
/// claim and never links.
#[test]
fn reuse_links_once_and_an_exhausted_incarnation_never_links() {
    let storage = storage_with(2);
    let live = storage.live_pool().unwrap();
    let first = completed(&storage, 100);
    let slot = first.id().slot_index();
    live.edit_word(slot, |word| word | VISITED);
    let transfer = first.release();
    storage.return_allocation(transfer, &mut budget()).unwrap();
    assert_eq!(live.word(slot) & VISITED, 0);
    assert_eq!(snapshot(&storage).1[slot], Node::CLEAR);

    // The claim visits the other slot before the returned one; exhausted,
    // the claim quarantines it and takes the returned slot.
    let other = 1 - slot;
    {
        let _gate = live.lock().unwrap();
        live.set_incarnation(other, u32::MAX);
    }
    let second = completed(&storage, 100);
    assert_eq!(second.id().slot_index(), slot);
    assert_eq!(
        storage.slot_state(SlotIndex(other)).unwrap().0,
        SlotState::Quarantined
    );
    let (list, nodes, _) = snapshot(&storage);
    assert_eq!(list, [slot]);
    assert_eq!(nodes[slot].state, LINKED);
    assert_eq!(nodes[other], Node::CLEAR);
    assert_eq!(live.word(slot) & VISITED, 0);
    drop(second);
}

/// The policy tables are fixed arrays of the control layout, sized from
/// the configuration alone: one 4-byte `next` link per slot, ending where
/// the domain record's alignment begins, one domain record and one pending
/// mark; `prev` sits in the slot record (pinned by the `slot` module's
/// layout test); the `init` tests' independent
/// layout checks their offsets and the page-rounded extent, which is
/// what `E` is charged. The engine charge does not
/// move through a whole lifecycle, extent returns refund nothing, and a
/// drained finalization unmaps the control extent that carries it.
#[test]
fn policy_bytes_are_charged_once_at_initialization() {
    let mut storage = storage_with(SLOTS);
    let inventory = storage.table_inventory().unwrap();
    assert_eq!(inventory.policy_next.1, SLOTS);
    assert_eq!(
        inventory.domain.0,
        (inventory.policy_next.0 + 4 * SLOTS).next_multiple_of(align_of::<Domain>())
    );
    assert_eq!(inventory.domain.1, 1);

    let used = storage.engine_used();
    for _ in 0..3 {
        let objects: Vec<_> = (0..4)
            .map(|i| completed(&storage, [8, 100][i % 2]))
            .collect();
        for object in objects {
            let transfer = object.release();
            storage.return_allocation(transfer, &mut budget()).unwrap();
        }
        assert_eq!(storage.engine_used(), used);
    }
    // Finalization recovers the policy bytes with the control extent that
    // holds them: every mapped range, that one included, is released once.
    let mut mapped = storage.platform.log().ranges(Op::Map);
    let control = &storage.pool.control;
    let extent = (control.base().as_ptr() as usize, control.len());
    assert!(mapped.contains(&extent), "{extent:?} in {mapped:?}");
    assert_eq!(control.len(), storage.pool_report().unwrap().control_extent);
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    mapped.reverse();
    assert_eq!(storage.platform.log().ranges(Op::Unmap), mapped);
    let control = storage.pool_report();
    assert!(control.is_none());
}

/// A volume whose slot table reaches `2^31 - 1` entries cannot be
/// addressed by policy links: validation refuses it, so no initialization
/// maps anything for it.
#[test]
fn a_volume_its_links_cannot_address_is_refused_before_any_mapping() {
    let limit = (1usize << 31) - 1;
    let mut accepted = config(limit - 1);
    accepted.volume.raw_bytes = 18 * crate::storage::IO_UNIT;
    assert!(accepted.validate().is_ok());
    let mut refused = config(limit);
    refused.volume.raw_bytes = 18 * crate::storage::IO_UNIT;
    assert_eq!(
        refused.validate(),
        Err(super::config::ConfigError::TableIndexLimit { slot_count: limit })
    );
}

#[test]
fn fill_records_whose_sum_overflows_usize_are_refused_at_the_root_layout() {
    use crate::index::{IndexConfig, Key, Ratio, ShardLimits};
    const SHARDS: usize = 65;
    let config = config(SHARDS).validate().unwrap();
    let limits = [1; SHARDS];
    let fills = [isize::MAX as usize / size_of::<Key>(); SHARDS];
    assert!(
        fills
            .iter()
            .try_fold(0usize, |sum, &f| sum.checked_add(f))
            .is_none()
    );
    let index = IndexConfig {
        shards: ShardLimits::Explicit(&limits),
        load: Ratio {
            numerator: 1,
            denominator: 2,
        },
        overflow: Ratio {
            numerator: 1,
            denominator: 1,
        },
        depth: 1,
        batch_max: 4,
        fills: &fills,
    }
    .validate(&config)
    .unwrap();
    let placement = PlacementConfig { control_home: 0 };
    let failure = Storage::initialize_indexed(&config, index, &placement, TestPlatform::heap(PAGE))
        .err()
        .expect("refused");
    assert!(
        matches!(
            failure.error,
            super::init::InitError::ControlLayoutOverflow {
                region: super::mapping::Region::Root
            }
        ),
        "{:?}",
        failure.error
    );
}

/// `bind` and the restored install's lanes are the only production writers of
/// `Resident`: every other store of the state in the storage sources lies
/// inside a test module.
#[test]
fn bind_and_the_restored_install_are_the_only_production_resident_writers() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage");
    let mut production = Vec::new();
    let mut dirs = vec![std::path::PathBuf::from(dir)];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let tests = source
                .find("#[cfg(test)]\nmod tests")
                .unwrap_or(source.len());
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.ends_with("_tests.rs") || name.ends_with("_model.rs") {
                continue;
            }
            for pattern in [
                "SlotState::Filling, SlotState::Resident",
                "SlotState::Resident.bits() | MARKER",
            ] {
                for (at, _) in source.match_indices(pattern) {
                    if at < tests {
                        production.push(name.clone());
                    }
                }
            }
        }
    }
    production.sort();
    assert_eq!(production, ["allocation.rs", "lanes.rs"]);
}

/// Binding, abandoning, sighting and returning allocate nothing, with the
/// policy hooks on every one of those paths.
#[test]
fn the_hooked_paths_allocate_nothing() {
    let storage = storage_with(4);
    let live = storage.live_pool().unwrap();
    let allocation = storage.reserve(Some(1), Some(8), &mut budget()).unwrap();
    let (resident, lease) = completed(&storage, 100)
        .handoff(&mut budget())
        .ok()
        .unwrap();
    let before = crate::instrument::allocations();
    let object = allocation
        .complete([9; 32], u64::MAX, &mut budget())
        .ok()
        .unwrap();
    drop(object);
    let gate = live.lock().unwrap();
    resident.retire();
    drop(gate);
    let mut spent = WorkBudget::new(1000);
    let _ = storage.certify(&mut spent).unwrap();
    storage.service(&mut spent).unwrap();
    drop(lease);
    let _ = storage.certify(&mut spent).unwrap();
    storage.service(&mut spent).unwrap();
    assert_eq!(crate::instrument::allocations(), before);
    assert_eq!(snapshot(&storage).2, 0);
}

/// The tables of a queue over `slots` free slots: their records, the `next`
/// table and an empty domain.
fn fresh(slots: usize) -> (Vec<Record>, Vec<u32>, Domain) {
    let records = (0..slots).map(|_| Record::free()).collect();
    (records, vec![POLICY_NONE; slots], Domain::EMPTY)
}

/// Everything a queue call can change: the domain, the `next` table, and
/// each slot's word and `prev` link.
type State = (Domain, Vec<u32>, Vec<(u64, u32)>);

fn state(records: &[Record], next: &[u32], domain: &Domain) -> State {
    let slots = records
        .iter()
        .map(|record| (record.word(), record.prev()))
        .collect();
    (*domain, next.to_vec(), slots)
}

/// Plants stale state in slot 1 of a two-slot queue.
type Plant = fn(&[Record], &mut [u32]);

/// Runs `call` on the queue and asserts that it panics with `message` and
/// leaves the queue's whole state as it found it.
fn assert_refused(
    records: &[Record],
    next: &mut [u32],
    domain: &mut Domain,
    message: &str,
    call: impl FnOnce(&mut Queue<'_, Record>),
) {
    let before = state(records, next, domain);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut queue = Queue::new(records, next, domain);
        call(&mut queue);
    }));
    let after = state(records, next, domain);
    let panic = outcome.expect_err(&format!(
        "the queue accepted the call it must refuse with `{message}`; state before {before:?}, after {after:?}"
    ));
    let text = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(text.contains(message), "panicked with `{text}`");
    assert_eq!(after, before, "the refused call changed the queue");
}

/// A second `mark_evicted` of an evicted slot panics with the word, the list
/// and the in-flight counts unchanged, whether the first mark found the slot
/// linked, already detached or never linked, and the write closure of
/// `mark_evicted_with` never runs.
#[test]
fn a_second_eviction_mark_panics_and_changes_nothing() {
    let (records, mut next, mut domain) = fresh(2);
    {
        let mut queue = Queue::new(&records, &mut next, &mut domain);
        queue.link(0);
        queue.link(1);
        assert!(queue.mark_evicted(0, 3), "the first mark detaches a member");
        assert!(queue.detach(1));
        assert!(
            !queue.mark_evicted(1, 5),
            "the first mark of a detached slot"
        );
    }
    assert_eq!(
        (domain.members, domain.detached, domain.in_flight),
        (0, 2, 2)
    );
    assert_eq!(domain.in_flight_units, 8);
    for record in &records {
        assert_eq!(
            record.word() & (LINKED | DETACHED | EVICTED),
            DETACHED | EVICTED
        );
    }

    for slot in 0..2 {
        assert_refused(&records, &mut next, &mut domain, "evicted twice", |queue| {
            queue.mark_evicted(slot, 7);
        });
        let mut wrote = false;
        assert_refused(&records, &mut next, &mut domain, "evicted twice", |queue| {
            queue.mark_evicted_with(slot, 7, |_| wrote = true);
        });
        assert!(!wrote, "the check runs before the word's write");
    }

    // An evicted slot that was never linked: its `EVICTED` bit alone makes
    // the second mark panic.
    let (records, mut next, mut domain) = fresh(1);
    Queue::new(&records, &mut next, &mut domain).mark_evicted(0, 2);
    assert_eq!(records[0].word() & (LINKED | DETACHED | EVICTED), EVICTED);
    assert_refused(&records, &mut next, &mut domain, "evicted twice", |queue| {
        queue.mark_evicted(0, 2);
    });
}

/// `link_with` panics for a slot with a stale `prev`, a stale `next` or a
/// policy bit, before it writes and before the list changes.
#[test]
fn a_link_of_a_slot_with_stale_state_panics_and_changes_nothing() {
    const MESSAGE: &str = "a resident slot linked twice or linked with stale state";
    let stale: [(&str, Plant); 5] = [
        ("prev", |records, _| records[1].set_prev(0)),
        ("next", |_, next| next[1] = 0),
        ("LINKED", |records, _| records[1].set_bits(LINKED)),
        ("DETACHED", |records, _| records[1].set_bits(DETACHED)),
        ("EVICTED", |records, _| records[1].set_bits(EVICTED)),
    ];
    for (what, plant) in stale {
        let (records, mut next, mut domain) = fresh(2);
        Queue::new(&records, &mut next, &mut domain).link(0);
        plant(&records, &mut next);
        let mut wrote = false;
        assert_refused(&records, &mut next, &mut domain, MESSAGE, |queue| {
            queue.link_with(1, |_| wrote = true);
        });
        assert!(!wrote, "stale {what}: the check runs before the write");
        assert_eq!((domain.head, domain.members), (0, 1), "stale {what}");
    }
    // A linked slot linked again.
    let (records, mut next, mut domain) = fresh(1);
    Queue::new(&records, &mut next, &mut domain).link(0);
    assert_refused(&records, &mut next, &mut domain, MESSAGE, |queue| {
        queue.link(0);
    });
}

/// `detach` and `mark_evicted` panic for a linked slot that carries a second
/// policy bit, with the slot still on the list and every count as it was.
#[test]
fn a_member_with_a_second_policy_bit_panics_and_changes_nothing() {
    const MESSAGE: &str = "a member with a second policy bit";
    let (records, mut next, mut domain) = fresh(2);
    {
        let mut queue = Queue::new(&records, &mut next, &mut domain);
        queue.link(0);
        queue.link(1);
    }
    records[0].set_bits(DETACHED);
    let mut wrote = false;
    assert_refused(&records, &mut next, &mut domain, MESSAGE, |queue| {
        queue.detach(0);
    });
    assert_refused(&records, &mut next, &mut domain, MESSAGE, |queue| {
        queue.detach_with(0, |_| wrote = true);
    });
    assert_refused(&records, &mut next, &mut domain, MESSAGE, |queue| {
        queue.mark_evicted(0, 4);
    });
    assert_refused(&records, &mut next, &mut domain, MESSAGE, |queue| {
        queue.mark_evicted_with(0, 4, |_| wrote = true);
    });
    assert!(!wrote, "the check runs before the word's write");
    assert_eq!(
        (domain.members, domain.detached, domain.in_flight),
        (2, 0, 0)
    );
}

/// `detach` panics for a linked slot that also carries `EVICTED`, a word
/// `mark_evicted` refuses as evicted twice ahead of its member check: the
/// slot stays on the list, the write closure of `detach_with` never runs
/// and every count is as it was.
#[test]
fn a_member_carrying_the_evicted_bit_refuses_its_detach_and_changes_nothing() {
    const MESSAGE: &str = "a member with a second policy bit";
    let (records, mut next, mut domain) = fresh(2);
    {
        let mut queue = Queue::new(&records, &mut next, &mut domain);
        queue.link(0);
        queue.link(1);
    }
    records[0].set_bits(EVICTED);
    assert_eq!(
        records[0].word() & (LINKED | DETACHED | EVICTED),
        LINKED | EVICTED
    );
    let mut wrote = false;
    assert_refused(&records, &mut next, &mut domain, MESSAGE, |queue| {
        queue.detach(0);
    });
    assert_refused(&records, &mut next, &mut domain, MESSAGE, |queue| {
        queue.detach_with(0, |_| wrote = true);
    });
    assert!(!wrote, "the check runs before the word's write");
    assert_eq!(
        (domain.members, domain.detached, domain.in_flight),
        (2, 0, 0)
    );
}
