//! The request namespace over records and rows of two operations: routing by wire identity and operation, admission refusals that build no record and change nothing, per-peer shares across operations, session retirement and exact release.

use crate::storage::EngineBudget;

use super::datagram::PeerId;
use super::namespace::{Cached, Namespace, Operated, Operation, Refusal, Route, WireSlot};
use super::requests::{
    GENERATION_LIMIT, MAX_REQUEST_SLOTS, RequestCensus, RequestId, RequestPressure, RequestTable,
};

/// A record or row standing for one request of `operation`, named by its wire identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tagged {
    operation: Operation,
    wire: u64,
}

impl Operated for Tagged {
    fn operation(&self) -> Operation {
        self.operation
    }
}

const WIDTH: u32 = 4;

/// Two peers sharing four table slots, two each, with four wire slots apiece.
fn namespace() -> Namespace<Tagged, Tagged> {
    Namespace::new(
        RequestTable::new(4, 2, 2),
        WIDTH,
        &mut EngineBudget::new(1 << 16),
    )
    .unwrap()
}

fn wire(slot: u16, generation: u64) -> RequestId {
    RequestId::from_wire(u64::from(slot) << 48 | generation)
}

fn record(operation: Operation, wire: RequestId) -> Tagged {
    Tagged {
        operation,
        wire: wire.wire(),
    }
}

/// Record builder for refused admissions; calling it fails the test.
fn unbuilt() -> Tagged {
    panic!("a refused admission builds no record")
}

fn row(operation: Operation, wire: RequestId, expires_us: u64) -> Cached<Tagged> {
    Cached {
        epoch: 1,
        expires_us,
        outcome: record(operation, wire),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    watermark: Option<u64>,
    active: Option<RequestId>,
    cached: Option<(u64, u64, Tagged)>,
}

fn snapshot(names: &Namespace<Tagged, Tagged>) -> Vec<Snapshot> {
    (0..2)
        .flat_map(|peer| (0..WIDTH as u16).map(move |slot| (peer, slot)))
        .map(|(peer, slot)| {
            let slot: WireSlot<Tagged> = names.slot(PeerId(peer), slot).unwrap();
            Snapshot {
                watermark: slot.watermark,
                active: slot.active,
                cached: slot
                    .cached
                    .map(|row| (row.epoch, row.expires_us, row.outcome)),
            }
        })
        .collect()
}

/// A wire identity routes by its generation against the slot's watermark: older below it, the slot's request and row at it, fresh above it or on an empty slot, and outside past the width or the peers.
#[test]
fn a_wire_identity_routes_by_its_generation() {
    let mut names = namespace();
    let peer = PeerId(0);
    assert!(matches!(
        names.route(peer, wire(0, 3), Operation::Get),
        Route::Fresh
    ));
    let id = names
        .admit(peer, wire(0, 3), || record(Operation::Get, wire(0, 3)))
        .unwrap();
    assert!(matches!(
        names.route(peer, wire(0, 2), Operation::Get),
        Route::Older
    ));
    assert!(matches!(
        names.route(peer, wire(0, 3), Operation::Get),
        Route::Same { active: Some(active), cached: None } if active == id
    ));
    assert!(matches!(
        names.route(peer, wire(0, 4), Operation::Put),
        Route::Fresh
    ));
    assert!(matches!(
        names.route(peer, wire(WIDTH as u16, 1), Operation::Get),
        Route::Outside
    ));
    assert!(matches!(
        names.route(PeerId(2), wire(0, 1), Operation::Get),
        Route::Outside
    ));
    assert_eq!(names.wrong_operation(), 0);
}

/// A frame of one operation naming a generation whose live request, or whose retained row, expired or not, belongs to the other operation changes nothing but the wrong-operation count; a fresh generation of the other operation routes as fresh.
#[test]
fn a_frame_naming_another_operations_request_or_row_changes_nothing_but_a_count() {
    let mut names = namespace();
    let peer = PeerId(1);
    let get = wire(1, 5);
    let id = names
        .admit(peer, get, || record(Operation::Get, get))
        .unwrap();
    let census = names.census();
    let before = snapshot(&names);
    assert!(matches!(
        names.route(peer, get, Operation::Put),
        Route::WrongOperation
    ));
    assert_eq!(names.wrong_operation(), 1);
    names.retain(peer, get.slot(), id, row(Operation::Get, get, 10));
    assert!(names.release(id, peer, get.slot()));
    assert!(matches!(
        names.route(peer, get, Operation::Put),
        Route::WrongOperation
    ));
    assert_eq!(names.wrong_operation(), 2);
    assert!(matches!(
        names.route(peer, get, Operation::Get),
        Route::Same {
            active: None,
            cached: Some(_)
        }
    ));
    assert_eq!(names.census().live(), census.live() - 1);
    assert_eq!(
        snapshot(&names)[4 + 1].watermark,
        before[4 + 1].watermark,
        "the watermark stays"
    );
    assert!(matches!(
        names.route(peer, wire(1, 6), Operation::Put),
        Route::Fresh
    ));
    let put = names
        .admit(peer, wire(1, 6), || record(Operation::Put, wire(1, 6)))
        .unwrap();
    assert!(matches!(
        names.route(peer, wire(1, 6), Operation::Get),
        Route::WrongOperation
    ));
    assert!(matches!(
        names.route(peer, wire(1, 6), Operation::Put),
        Route::Same { active: Some(active), cached: None } if active == put
    ));
    assert_eq!(names.wrong_operation(), 3);
}

/// Every admission refusal leaves `unbuilt` uncalled and the table, the census, every watermark and every binding unchanged: a slot outside the namespace, a slot with a live request even at the last generation, the last generation on a free slot, and a full peer share.
#[test]
fn a_refused_admission_builds_no_record_and_changes_nothing() {
    let mut names = namespace();
    let peer = PeerId(0);
    let id = names
        .admit(peer, wire(0, 1), || record(Operation::Get, wire(0, 1)))
        .unwrap();
    names.retain(peer, 0, id, row(Operation::Get, wire(0, 1), 10));
    for slot in [1, 3] {
        let old = wire(slot, 0);
        let id = names
            .admit(peer, old, || record(Operation::Get, old))
            .unwrap();
        names.retain(peer, slot, id, row(Operation::Get, old, 20));
        assert!(names.release(id, peer, slot));
    }
    let cases = [
        (wire(WIDTH as u16, 1), Refusal::Outside),
        (wire(0, 2), Refusal::Busy),
        (wire(0, GENERATION_LIMIT), Refusal::Busy),
        (wire(1, GENERATION_LIMIT), Refusal::Exhausted),
    ];
    for (wire, refusal) in cases {
        let (census, slots) = (names.census(), snapshot(&names));
        assert_eq!(names.admit(peer, wire, unbuilt), Err(refusal));
        assert_eq!((names.census(), snapshot(&names)), (census, slots));
    }
    names
        .admit(peer, wire(2, 1), || record(Operation::Put, wire(2, 1)))
        .unwrap();
    let (census, slots) = (names.census(), snapshot(&names));
    assert_eq!(
        names.admit(peer, wire(3, 1), unbuilt),
        Err(Refusal::Pressure(RequestPressure::Peer))
    );
    assert_eq!((names.census(), snapshot(&names)), (census, slots));
}

/// Requests of both operations draw on one per-peer share: a peer holding one GET and one PUT is refused a third request while the other peer's share stays admissible, and a release returns the share.
#[test]
fn mixed_operations_exhaust_only_their_own_peers_share() {
    let mut names = namespace();
    let (first, second) = (PeerId(0), PeerId(1));
    let get = names
        .admit(first, wire(0, 1), || record(Operation::Get, wire(0, 1)))
        .unwrap();
    names
        .admit(first, wire(1, 1), || record(Operation::Put, wire(1, 1)))
        .unwrap();
    assert!(matches!(
        names.admit(first, wire(2, 1), unbuilt),
        Err(Refusal::Pressure(RequestPressure::Peer))
    ));
    for (slot, operation) in [(0, Operation::Put), (1, Operation::Get)] {
        names
            .admit(second, wire(slot, 1), || record(operation, wire(slot, 1)))
            .unwrap();
    }
    assert_eq!(names.table().peer_census(first).active, 2);
    assert_eq!(names.table().peer_census(second).active, 2);
    assert!(names.release(get, first, 0));
    names
        .admit(first, wire(2, 1), || record(Operation::Get, wire(2, 1)))
        .unwrap();
}

/// Retiring a session forgets the peer's watermarks and rows and keeps each slot's draining request bound, so a fresh request waits for the drain; the release clears only its own binding, and an older handle released against the slot leaves a newer binding in place.
#[test]
fn retirement_forgets_evidence_and_keeps_a_drain_bound_until_its_own_release() {
    let mut names = namespace();
    let peer = PeerId(0);
    let old = names
        .admit(peer, wire(0, 7), || record(Operation::Put, wire(0, 7)))
        .unwrap();
    names.retain(peer, 0, old, row(Operation::Put, wire(0, 7), u64::MAX));
    assert!(names.begin_drain(old));
    names.retire(peer);
    let slot = names.slot(peer, 0).unwrap();
    assert_eq!((slot.watermark, slot.active), (None, Some(old)));
    assert!(names.slot(peer, 0).unwrap().cached.is_none(), "rows clear");
    assert!(matches!(
        names.route(peer, wire(0, 1), Operation::Get),
        Route::Fresh
    ));
    assert!(matches!(
        names.admit(peer, wire(0, 1), unbuilt),
        Err(Refusal::Busy)
    ));
    assert_eq!(names.census().draining, 1, "the drain keeps its share");
    let other = names
        .admit(peer, wire(2, 1), || record(Operation::Get, wire(2, 1)))
        .unwrap();
    names.retain(peer, 2, old, row(Operation::Put, wire(0, 7), 30));
    assert!(names.slot(peer, 2).unwrap().cached.is_none());
    assert!(!names.release(other, peer, 0));
    assert!(names.table().get(other).is_some());
    assert!(names.release(other, peer, 2));
    assert_eq!(
        names.slot(peer, 0).unwrap().active,
        Some(old),
        "a release against another request's slot leaves that binding"
    );
    assert!(names.release(old, peer, 0));
    assert_eq!(names.slot(peer, 0).unwrap().active, None);
    assert!(!names.release(old, peer, 0), "a released handle is stale");
    names
        .admit(peer, wire(0, 1), || record(Operation::Get, wire(0, 1)))
        .unwrap();
}

/// The namespace charges its wire slots once and refuses a budget below that charge with the budget unchanged; routing and admission allocate nothing.
#[test]
fn the_namespace_charges_once_and_routes_without_allocating() {
    let charge = Namespace::<Tagged, Tagged>::charge(WIDTH, 2, 4).unwrap();
    let mut short = EngineBudget::new(charge - 1);
    assert!(
        Namespace::<Tagged, Tagged>::new(RequestTable::new(4, 2, 2), WIDTH, &mut short).is_err()
    );
    assert_eq!(short.used(), 0);
    let mut exact = EngineBudget::new(charge);
    let mut names = Namespace::new(RequestTable::new(4, 2, 2), WIDTH, &mut exact).unwrap();
    assert_eq!(exact.used(), charge);
    let allocations = crate::instrument::allocations();
    let id = names
        .admit(PeerId(0), wire(0, 1), || record(Operation::Get, wire(0, 1)))
        .unwrap();
    let _ = names.route(PeerId(0), wire(0, 1), Operation::Put);
    names.retain(PeerId(0), 0, id, row(Operation::Get, wire(0, 1), 5));
    assert!(names.release(id, PeerId(0), 0));
    names.retire(PeerId(0));
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// The namespace calls of [`released_generations_preserve_evidence`], so one
/// history runs over the production namespace and over a planted defect.
trait Names {
    fn admit(
        &mut self,
        peer: PeerId,
        wire: RequestId,
        build: impl FnOnce() -> Tagged,
    ) -> Result<RequestId, Refusal>;
    fn retain(&mut self, peer: PeerId, slot: u16, id: RequestId, cached: Cached<Tagged>);
    fn release(&mut self, id: RequestId, peer: PeerId, slot: u16) -> bool;
    fn slot(&self, peer: PeerId, slot: u16) -> Option<WireSlot<Tagged>>;
    fn census(&self) -> RequestCensus;
}

impl Names for Namespace<Tagged, Tagged> {
    fn admit(
        &mut self,
        peer: PeerId,
        wire: RequestId,
        build: impl FnOnce() -> Tagged,
    ) -> Result<RequestId, Refusal> {
        Namespace::admit(self, peer, wire, build)
    }

    fn retain(&mut self, peer: PeerId, slot: u16, id: RequestId, cached: Cached<Tagged>) {
        Namespace::retain(self, peer, slot, id, cached);
    }

    fn release(&mut self, id: RequestId, peer: PeerId, slot: u16) -> bool {
        Namespace::release(self, id, peer, slot)
    }

    fn slot(&self, peer: PeerId, slot: u16) -> Option<WireSlot<Tagged>> {
        Namespace::slot(self, peer, slot)
    }

    fn census(&self) -> RequestCensus {
        Namespace::census(self)
    }
}

/// A namespace whose release also forgets the peer's watermarks and retained
/// rows, as only a session retirement may. Its slot accepts a generation the
/// session already admitted, so one wire identity is admitted twice.
struct ForgetfulRelease(Namespace<Tagged, Tagged>);

impl Names for ForgetfulRelease {
    fn admit(
        &mut self,
        peer: PeerId,
        wire: RequestId,
        build: impl FnOnce() -> Tagged,
    ) -> Result<RequestId, Refusal> {
        self.0.admit(peer, wire, build)
    }

    fn retain(&mut self, peer: PeerId, slot: u16, id: RequestId, cached: Cached<Tagged>) {
        self.0.retain(peer, slot, id, cached);
    }

    fn release(&mut self, id: RequestId, peer: PeerId, slot: u16) -> bool {
        let released = self.0.release(id, peer, slot);
        self.0.retire(peer);
        released
    }

    fn slot(&self, peer: PeerId, slot: u16) -> Option<WireSlot<Tagged>> {
        self.0.slot(peer, slot)
    }

    fn census(&self) -> RequestCensus {
        self.0.census()
    }
}

/// A released generation and every one below it stay refused as stale, with the
/// watermark and the retained row in place, until a higher generation is
/// admitted; the old handle then neither retains nor releases on the slot.
#[test]
fn released_generations_preserve_evidence_until_fresh_admission() {
    released_generations_preserve_evidence(namespace());
}

/// The control for the stale refusal: a release that forgets the slot's
/// watermark lets the history's first re-admission of a released generation
/// build a record, so `unbuilt` fails it.
#[test]
#[should_panic(expected = "a refused admission builds no record")]
fn negative_control_a_release_that_forgets_the_watermark_readmits_a_released_identity() {
    released_generations_preserve_evidence(ForgetfulRelease(namespace()));
}

fn released_generations_preserve_evidence(mut names: impl Names) {
    let peer = PeerId(0);
    let old = wire(0, 3);
    let id = names
        .admit(peer, old, || record(Operation::Get, old))
        .unwrap();
    names.retain(peer, 0, id, row(Operation::Get, old, 10));
    assert!(names.release(id, peer, 0));
    for generation in [0, 2, 3] {
        let wire = wire(0, generation);
        assert_eq!(names.admit(peer, wire, unbuilt), Err(Refusal::Stale));
        let slot = names.slot(peer, 0).unwrap();
        assert_eq!(slot.watermark, Some(3));
        assert_eq!(slot.cached.unwrap().outcome, record(Operation::Get, old));
        assert_eq!(names.census().live(), 0);
    }
    let next = wire(0, 4);
    let newer = names
        .admit(peer, next, || record(Operation::Put, next))
        .unwrap();
    names.retain(peer, 0, id, row(Operation::Get, old, 20));
    assert!(!names.release(id, peer, 0));
    assert_eq!(names.slot(peer, 0).unwrap().active, Some(newer));
    assert!(names.slot(peer, 0).unwrap().cached.is_none());
    assert_eq!(names.census().active, 1);
}

#[test]
fn table_pressure_preserves_an_unused_wire_slot() {
    let mut names: Namespace<Tagged, Tagged> = Namespace::new(
        RequestTable::new(1, 2, 1),
        WIDTH,
        &mut EngineBudget::new(4096),
    )
    .unwrap();
    let first = wire(0, 1);
    names
        .admit(PeerId(0), first, || record(Operation::Get, first))
        .unwrap();
    assert_eq!(
        names.admit(PeerId(1), first, unbuilt),
        Err(Refusal::Pressure(RequestPressure::Table))
    );
    let slot = names.slot(PeerId(1), 0).unwrap();
    assert_eq!((slot.watermark, slot.active), (None, None));
    assert!(slot.cached.is_none());
    assert_eq!(names.table().peer_census(PeerId(1)).active, 0);
    assert_eq!(names.census().active, 1);
}

#[test]
fn unbinding_preserves_custody_and_release_preserves_a_successor() {
    let mut names = namespace();
    let peer = PeerId(0);
    let old_wire = wire(0, 3);
    let old = names
        .admit(peer, old_wire, || record(Operation::Get, old_wire))
        .unwrap();
    names.retain(peer, 0, old, row(Operation::Get, old_wire, 10));
    names.begin_drain(old);
    let before = snapshot(&names);
    for (peer, slot, id) in [
        (PeerId(1), 0, old),
        (peer, 1, old),
        (peer, 0, wire(old.slot(), old.generation() + 1)),
    ] {
        names.unbind(peer, slot, id);
        assert_eq!(snapshot(&names), before);
    }
    names.unbind(peer, 0, old);
    let slot = names.slot(peer, 0).unwrap();
    assert_eq!(slot.active, None);
    assert_eq!(slot.watermark, Some(3));
    assert_eq!(
        slot.cached.unwrap().outcome,
        record(Operation::Get, old_wire)
    );
    assert_eq!(names.census().draining, 1);
    assert!(matches!(
        names.route(peer, old_wire, Operation::Get),
        Route::Same {
            active: None,
            cached: Some(_)
        }
    ));
    let next_wire = wire(0, 4);
    let next = names
        .admit(peer, next_wire, || record(Operation::Get, next_wire))
        .unwrap();
    assert_ne!(next.slot(), old.slot(), "custody keeps the old table slot");
    assert!(matches!(
        names.route(peer, old_wire, Operation::Get),
        Route::Older
    ));
    assert_eq!(names.census().live(), 2);
    names.unbind(peer, 0, old);
    assert_eq!(names.slot(peer, 0).unwrap().active, Some(next));
    assert!(!names.release(old, PeerId(1), 0));
    assert!(names.release(old, peer, 0));
    assert_eq!(names.slot(peer, 0).unwrap().active, Some(next));
    assert_eq!(names.slot(peer, 0).unwrap().watermark, Some(4));
    assert!(names.slot(peer, 0).unwrap().cached.is_none());
    assert!(!names.release(old, peer, 0));
    let reused_wire = wire(1, 5);
    let reused = names
        .admit(peer, reused_wire, || record(Operation::Get, reused_wire))
        .unwrap();
    assert_eq!(reused.slot(), old.slot());
    assert_ne!(reused.generation(), old.generation());
    assert!(
        !names.release(reused, peer, 0),
        "the unbound bit cleared with the old record"
    );
    assert!(names.release(reused, peer, 1));
    assert!(names.release(next, peer, 0));
    assert_eq!(names.census().live(), 0);
}

#[test]
fn unbound_draining_records_refuse_reuse_as_peer_share_pressure() {
    let mut names = namespace();
    let peer = PeerId(0);
    let mut ids = Vec::new();
    for slot in 0..2 {
        let request = wire(slot, 1);
        let id = names
            .admit(peer, request, || record(Operation::Get, request))
            .unwrap();
        names.begin_drain(id);
        names.unbind(peer, slot, id);
        ids.push(id);
    }
    let before = (snapshot(&names), names.census());
    assert_eq!(
        names.admit(peer, wire(0, 2), unbuilt),
        Err(Refusal::Pressure(RequestPressure::Peer))
    );
    assert_eq!((snapshot(&names), names.census()), before);
    assert_eq!(names.table().peer_census(peer).draining, 2);
    for (slot, id) in ids.into_iter().enumerate() {
        assert!(names.release(id, peer, slot as u16));
    }
    assert_eq!(names.census().live(), 0);
}

/// A settled fresh identity is admitted at most once. On a free binding the
/// answer becomes the slot's row at that generation, so the identity routes
/// to it and admission refuses it as stale; a higher generation admits. A
/// generation at or below the watermark, at the limit, or outside the
/// namespace settles nothing.
#[test]
fn a_settled_fresh_identity_routes_to_its_answer_and_admits_no_request() {
    let mut names = namespace();
    let peer = PeerId(0);
    let refused = wire(0, 3);
    names.settle(peer, refused, Some(row(Operation::Put, refused, 10)));
    let slot = names.slot(peer, 0).unwrap();
    assert_eq!((slot.watermark, slot.active), (Some(3), None));
    assert_eq!(
        slot.cached.unwrap().outcome,
        record(Operation::Put, refused)
    );
    assert!(matches!(
        names.route(peer, refused, Operation::Put),
        Route::Same {
            active: None,
            cached: Some(_)
        }
    ));
    assert_eq!(
        names.admit(peer, refused, unbuilt).err(),
        Some(Refusal::Stale)
    );
    assert!(matches!(
        names.route(peer, wire(0, 2), Operation::Put),
        Route::Older
    ));
    let before = snapshot(&names);
    names.settle(peer, wire(0, 2), Some(row(Operation::Put, wire(0, 2), 10)));
    names.settle(peer, refused, Some(row(Operation::Get, refused, 20)));
    names.settle(peer, refused, None);
    names.settle(
        peer,
        wire(1, GENERATION_LIMIT),
        Some(row(Operation::Put, wire(1, GENERATION_LIMIT), 10)),
    );
    names.settle(
        PeerId(2),
        wire(0, 1),
        Some(row(Operation::Put, wire(0, 1), 10)),
    );
    names.settle(
        peer,
        wire(WIDTH as u16, 1),
        Some(row(Operation::Put, wire(WIDTH as u16, 1), 10)),
    );
    assert_eq!(snapshot(&names), before);
    let next = wire(0, 4);
    let id = names
        .admit(peer, next, || record(Operation::Put, next))
        .unwrap();
    assert_eq!(names.slot(peer, 0).unwrap().active, Some(id));
    assert_eq!(names.slot(peer, 0).unwrap().watermark, Some(4));
    assert!(names.slot(peer, 0).unwrap().cached.is_none());
}

#[test]
fn an_identity_settled_with_no_row_routes_to_an_empty_slot_and_admits_no_request() {
    let mut names = namespace();
    let peer = PeerId(0);
    let ended = wire(0, 2);
    let id = names
        .admit(peer, ended, || record(Operation::Put, ended))
        .unwrap();
    names.retain(peer, 0, id, row(Operation::Put, ended, 10));
    assert!(names.release(id, peer, 0));
    let settled = wire(0, 3);
    names.settle(peer, settled, None);
    let slot = names.slot(peer, 0).unwrap();
    assert_eq!(
        (slot.watermark, slot.active, slot.refused),
        (Some(3), None, None)
    );
    assert!(slot.cached.is_none());
    for operation in [Operation::Put, Operation::Get] {
        assert!(
            matches!(
                names.route(peer, settled, operation),
                Route::Same {
                    active: None,
                    cached: None
                }
            ),
            "{operation:?}"
        );
    }
    assert_eq!(names.wrong_operation(), 0);
    assert!(matches!(
        names.route(peer, ended, Operation::Put),
        Route::Older
    ));
    assert_eq!(
        names.admit(peer, settled, unbuilt).err(),
        Some(Refusal::Stale)
    );
    let next = wire(0, 4);
    assert!(
        names
            .admit(peer, next, || record(Operation::Put, next))
            .is_ok()
    );
}

const PEER: PeerId = PeerId(0);
const SLOT: u16 = 0;
/// The generation of the request that holds the binding on [`SLOT`].
const HELD: u64 = 3;
/// A generation that leaves a gap above [`HELD`].
const ABOVE: u64 = 5;

const OPERATIONS: [Operation; 2] = [Operation::Get, Operation::Put];

fn other(operation: Operation) -> Operation {
    match operation {
        Operation::Get => Operation::Put,
        Operation::Put => Operation::Get,
    }
}

/// A [`Route`] with its row reduced to the outcome, so two routes compare.
#[derive(Debug, PartialEq, Eq)]
enum Landed {
    Outside,
    Older,
    Same {
        active: Option<RequestId>,
        row: Option<Tagged>,
    },
    Fresh,
    WrongOperation,
}

fn landed(route: Route<Tagged>) -> Landed {
    match route {
        Route::Outside => Landed::Outside,
        Route::Older => Landed::Older,
        Route::Same { active, cached } => Landed::Same {
            active,
            row: cached.map(|row| row.outcome),
        },
        Route::Fresh => Landed::Fresh,
        Route::WrongOperation => Landed::WrongOperation,
    }
}

/// Wire slot [`SLOT`] of [`PEER`] as (watermark, binding, refused generation, retained row's outcome).
fn slot_state(
    names: &Namespace<Tagged, Tagged>,
) -> (Option<u64>, Option<RequestId>, Option<u64>, Option<Tagged>) {
    let slot = names.slot(PEER, SLOT).unwrap();
    (
        slot.watermark,
        slot.active,
        slot.refused,
        slot.cached.map(|row| row.outcome),
    )
}

/// How a bound request's binding frees.
#[derive(Debug, Clone, Copy)]
enum Free {
    /// The request drains and its sent terminal unbinds it; its record stays until release.
    DrainThenUnbind,
    /// The request's release drops the record and its binding in one call.
    Release,
}

/// Frees `held`'s binding on [`SLOT`] by `free`.
fn free_binding(names: &mut Namespace<Tagged, Tagged>, held: RequestId, free: Free) {
    match free {
        Free::DrainThenUnbind => {
            assert!(
                names.begin_drain(held),
                "the bound request begins its drain"
            );
            names.unbind(PEER, SLOT, held);
            assert_eq!(
                names.census().live(),
                1,
                "an unbound record stays until release"
            );
        }
        Free::Release => {
            assert!(
                names.release(held, PEER, SLOT),
                "the bound request releases"
            );
            assert_eq!(names.census().live(), 0);
        }
    }
}

/// Admits the request of `operation` at [`HELD`] on a new namespace and returns both.
fn held_request(operation: Operation) -> (Namespace<Tagged, Tagged>, RequestId) {
    let mut names = namespace();
    let held_wire = wire(SLOT, HELD);
    let held = names
        .admit(PEER, held_wire, || record(operation, held_wire))
        .unwrap();
    assert_eq!(slot_state(&names), (Some(HELD), Some(held), None, None));
    (names, held)
}

/// Runs the history of an identity refused under a held binding, for each pairing of the bound request's
/// operation with the refused identity's and for the generation next to [`HELD`] and the one a gap above it.
///
/// A request holds the slot at [`HELD`]. The identity at the refused generation is fresh, is refused `Busy`
/// and is settled with a row offered. While the binding lasts the slot records the generation as refused and
/// keeps no offered row, the identity stays `Busy`, and the bound request keeps its route and the row it
/// retains. The binding then frees by `free`. The freed slot shows the refused generation as its watermark
/// with no binding, no refused generation and no row; a retransmission of the refused identity routes
/// `Same` with no request and no row for either operation and counts no operation mismatch; the identity is
/// `Stale`, and stays unadmitted after the next generation is admitted and released.
///
/// `Route::Same` with no request and no row is the arm at which the GET core drops the frame and the PUT
/// core answers `Status::UnknownOutcome`; a row there would be replayed as the refused identity's answer.
fn the_refused_identity_keeps_no_row(free: Free) {
    let pairings = OPERATIONS
        .into_iter()
        .flat_map(|held| OPERATIONS.map(|refused| (held, refused)));
    for (held_operation, refused_operation) in pairings {
        for generation in [HELD + 1, ABOVE] {
            let case = format!(
                "{held_operation:?} bound, {refused_operation:?} refused at {generation}, freed by {free:?}"
            );
            let (mut names, held) = held_request(held_operation);
            let (held_wire, refused) = (wire(SLOT, HELD), wire(SLOT, generation));
            assert_eq!(
                landed(names.lookup(PEER, refused, refused_operation)),
                Landed::Fresh,
                "{case}"
            );
            assert_eq!(
                names.admit(PEER, refused, unbuilt).err(),
                Some(Refusal::Busy),
                "{case}"
            );
            names.settle(PEER, refused, Some(row(refused_operation, refused, 10)));
            assert_eq!(
                slot_state(&names),
                (Some(HELD), Some(held), Some(generation), None),
                "{case}: the settled generation is recorded as refused and the offered row is not kept"
            );
            assert_eq!(
                landed(names.route(PEER, held_wire, held_operation)),
                Landed::Same {
                    active: Some(held),
                    row: None
                },
                "{case}"
            );
            assert_eq!(
                names.admit(PEER, refused, unbuilt).err(),
                Some(Refusal::Busy),
                "{case}: the settled identity is refused as busy while the binding lasts"
            );
            assert_eq!(
                names.admissible(PEER, refused),
                Err(Refusal::Busy),
                "{case}"
            );
            // The bound request sends its terminal: the slot retains its row beside the refused generation.
            names.retain(PEER, SLOT, held, row(held_operation, held_wire, 10));
            let kept = Some(record(held_operation, held_wire));
            assert_eq!(
                slot_state(&names),
                (Some(HELD), Some(held), Some(generation), kept),
                "{case}"
            );
            assert_eq!(
                landed(names.route(PEER, held_wire, held_operation)),
                Landed::Same {
                    active: Some(held),
                    row: kept
                },
                "{case}: the bound request keeps its route and row"
            );
            assert_eq!(names.census().live(), 1, "{case}");
            free_binding(&mut names, held, free);

            assert_eq!(
                slot_state(&names),
                (Some(generation), None, None, None),
                "{case}: the freed slot holds the refused generation and no row"
            );
            let nothing = Landed::Same {
                active: None,
                row: None,
            };
            for operation in OPERATIONS {
                assert_eq!(
                    landed(names.lookup(PEER, refused, operation)),
                    nothing,
                    "{case}: a {operation:?} retransmission finds nothing to replay"
                );
                assert_eq!(
                    landed(names.route(PEER, refused, operation)),
                    nothing,
                    "{case}: a {operation:?} retransmission finds nothing to replay"
                );
            }
            assert_eq!(names.wrong_operation(), 0, "{case}");
            assert_eq!(
                names.admit(PEER, refused, unbuilt).err(),
                Some(Refusal::Stale),
                "{case}: the refused identity is stale once the binding frees"
            );
            assert_eq!(
                names.admissible(PEER, refused),
                Err(Refusal::Stale),
                "{case}"
            );
            assert_eq!(
                landed(names.route(PEER, held_wire, held_operation)),
                Landed::Older,
                "{case}: the freed request's generation lies below the watermark"
            );
            if matches!(free, Free::DrainThenUnbind) {
                // The unbound record's release drops the record and leaves the slot as the unbind left it.
                assert!(names.release(held, PEER, SLOT), "{case}");
                assert_eq!(
                    slot_state(&names),
                    (Some(generation), None, None, None),
                    "{case}"
                );
            }
            assert_eq!(names.census().live(), 0, "{case}");
            // A later generation admits; the refused identity then lies below the watermark for good.
            let next = wire(SLOT, generation + 1);
            let admitted = names.admit(PEER, next, || record(refused_operation, next));
            assert!(admitted.is_ok(), "{case}: {admitted:?}");
            assert_eq!(
                landed(names.route(PEER, refused, refused_operation)),
                Landed::Older,
                "{case}"
            );
            assert_eq!(
                names.admit(PEER, refused, unbuilt).err(),
                Some(Refusal::Busy),
                "{case}"
            );
            assert!(names.release(admitted.unwrap(), PEER, SLOT), "{case}");
            assert_eq!(
                names.admit(PEER, refused, unbuilt).err(),
                Some(Refusal::Stale),
                "{case}: the refused identity is never admitted"
            );
        }
    }
}

/// An identity settled while a request holds the binding is refused as busy
/// until the binding frees and as stale from then on, the bound request
/// keeps its route and row, and the binding's unbind raises the watermark to
/// the settled generation with no row, so the identity is never admitted.
#[test]
fn an_identity_settled_under_a_held_binding_is_refused_through_its_release() {
    the_refused_identity_keeps_no_row(Free::DrainThenUnbind);
}

/// The same history with the binding freed by the bound request's release alone.
#[test]
fn an_identity_settled_under_a_held_binding_keeps_no_row_once_release_frees_it() {
    the_refused_identity_keeps_no_row(Free::Release);
}

/// The same request, row and free with no identity refused: the slot keeps the request's generation and row,
/// the request's own retransmission routes to that row, and the generation above it is fresh and admits. The
/// row an identity refused under the binding requires gone is one a freed binding otherwise keeps.
#[test]
fn a_binding_freed_with_nothing_refused_keeps_its_watermark_and_row() {
    for free in [Free::DrainThenUnbind, Free::Release] {
        for operation in OPERATIONS {
            let case = format!("{operation:?} bound, freed by {free:?}");
            let (mut names, held) = held_request(operation);
            let (held_wire, above) = (wire(SLOT, HELD), wire(SLOT, ABOVE));
            names.retain(PEER, SLOT, held, row(operation, held_wire, 10));
            free_binding(&mut names, held, free);
            let kept = Some(record(operation, held_wire));
            assert_eq!(slot_state(&names), (Some(HELD), None, None, kept), "{case}");
            assert_eq!(
                landed(names.route(PEER, held_wire, operation)),
                Landed::Same {
                    active: None,
                    row: kept
                },
                "{case}: the request's own retransmission routes to its row"
            );
            assert_eq!(
                landed(names.lookup(PEER, held_wire, other(operation))),
                Landed::WrongOperation,
                "{case}: the kept row keeps its operation"
            );
            assert_eq!(
                names.admit(PEER, held_wire, unbuilt).err(),
                Some(Refusal::Stale),
                "{case}"
            );
            if matches!(free, Free::DrainThenUnbind) {
                assert!(names.release(held, PEER, SLOT), "{case}");
                assert_eq!(slot_state(&names), (Some(HELD), None, None, kept), "{case}");
            }
            assert_eq!(
                landed(names.lookup(PEER, above, operation)),
                Landed::Fresh,
                "{case}"
            );
            let admitted = names.admit(PEER, above, || record(operation, above));
            assert!(admitted.is_ok(), "{case}: {admitted:?}");
            assert_eq!(
                slot_state(&names),
                (Some(ABOVE), admitted.ok(), None, None),
                "{case}"
            );
        }
    }
}

/// A settle that names the last generation a wire identity carries, a slot at the namespace's width, a
/// peer past its peers, or a generation at or below the watermark changes nothing, whether the slot is
/// free or bound; a binding under which only such identities were settled frees with its watermark and row.
#[test]
fn a_settle_at_the_generation_limit_or_outside_the_namespace_changes_nothing() {
    let limit = wire(SLOT, GENERATION_LIMIT);
    let past_width = wire(WIDTH as u16, ABOVE);
    let past_peers = PeerId(2);
    let unsettled = |names: &mut Namespace<Tagged, Tagged>, state: &str| {
        let before = format!("{names:?}");
        for operation in OPERATIONS {
            for cached in [Some(row(operation, limit, 10)), None] {
                names.settle(PEER, limit, cached);
                assert_eq!(
                    format!("{names:?}"),
                    before,
                    "{state}: the generation limit"
                );
            }
            names.settle(PEER, past_width, Some(row(operation, past_width, 10)));
            assert_eq!(format!("{names:?}"), before, "{state}: a slot at the width");
            names.settle(
                past_peers,
                wire(SLOT, ABOVE),
                Some(row(operation, wire(SLOT, ABOVE), 10)),
            );
            assert_eq!(
                format!("{names:?}"),
                before,
                "{state}: a peer past the peers"
            );
        }
        assert_eq!(
            landed(names.lookup(PEER, past_width, Operation::Get)),
            Landed::Outside
        );
        assert_eq!(
            landed(names.lookup(past_peers, wire(SLOT, ABOVE), Operation::Get)),
            Landed::Outside
        );
        assert_eq!(
            names.admit(PEER, past_width, unbuilt).err(),
            Some(Refusal::Outside)
        );
        assert_eq!(format!("{names:?}"), before, "{state}: a refused admission");
    };

    let mut names = namespace();
    unsettled(&mut names, "a free slot");
    assert_eq!(slot_state(&names), (None, None, None, None));
    assert_eq!(
        landed(names.lookup(PEER, limit, Operation::Get)),
        Landed::Fresh
    );
    assert_eq!(
        names.admit(PEER, limit, unbuilt).err(),
        Some(Refusal::Exhausted)
    );

    for free in [Free::DrainThenUnbind, Free::Release] {
        let (mut names, held) = held_request(Operation::Put);
        let held_wire = wire(SLOT, HELD);
        names.retain(PEER, SLOT, held, row(Operation::Put, held_wire, 10));
        unsettled(&mut names, "a bound slot");
        let before = format!("{names:?}");
        for stale in [HELD - 1, HELD] {
            names.settle(
                PEER,
                wire(SLOT, stale),
                Some(row(Operation::Get, wire(SLOT, stale), 10)),
            );
            assert_eq!(
                format!("{names:?}"),
                before,
                "a generation at or below the watermark"
            );
        }
        let kept = Some(record(Operation::Put, held_wire));
        assert_eq!(slot_state(&names), (Some(HELD), Some(held), None, kept));
        free_binding(&mut names, held, free);
        assert_eq!(
            slot_state(&names),
            (Some(HELD), None, None, kept),
            "freed by {free:?}: nothing was refused, so the watermark and row stay"
        );
    }
}

/// A wire slot holds the highest admissible generation bound to the table's
/// last handle, slot 65535 at the generation limit, whose wire form sets
/// every bit: the slot reads back both, routes the generation to that handle,
/// refuses the next generation as busy, its unbind frees the binding and
/// keeps the watermark and row, and its release drops the record and keeps
/// the watermark.
#[test]
fn a_wire_slot_holds_the_highest_generation_bound_to_the_last_table_handle() {
    let mut names = Namespace::new(
        RequestTable::new(MAX_REQUEST_SLOTS, 1, MAX_REQUEST_SLOTS),
        1,
        &mut EngineBudget::new(1 << 26),
    )
    .unwrap();
    let peer = PeerId(0);
    let last = u16::try_from(MAX_REQUEST_SLOTS - 1).unwrap();
    names.start_slot_at(last, GENERATION_LIMIT);
    for generation in 1..u64::from(last) + 1 {
        let held = wire(0, generation);
        let id = names
            .admit(peer, held, || record(Operation::Get, held))
            .unwrap();
        names.begin_drain(id);
        names.unbind(peer, 0, id);
    }
    let top = wire(0, GENERATION_LIMIT - 1);
    let id = names
        .admit(peer, top, || record(Operation::Get, top))
        .unwrap();
    assert_eq!((id.slot(), id.generation()), (last, GENERATION_LIMIT));
    assert_eq!(id.wire(), u64::MAX);
    let slot = names.slot(peer, 0).unwrap();
    assert_eq!(
        (slot.watermark, slot.active, slot.refused),
        (Some(GENERATION_LIMIT - 1), Some(id), None)
    );
    assert!(matches!(
        names.route(peer, top, Operation::Get),
        Route::Same { active: Some(active), cached: None } if active == id
    ));
    assert!(matches!(
        names.route(peer, wire(0, GENERATION_LIMIT - 2), Operation::Get),
        Route::Older
    ));
    assert_eq!(
        names.admit(peer, wire(0, GENERATION_LIMIT), unbuilt).err(),
        Some(Refusal::Busy)
    );
    names.retain(peer, 0, id, row(Operation::Get, top, 10));
    names.begin_drain(id);
    names.unbind(peer, 0, id);
    let slot = names.slot(peer, 0).unwrap();
    assert_eq!(
        (slot.watermark, slot.active),
        (Some(GENERATION_LIMIT - 1), None)
    );
    assert_eq!(slot.cached.unwrap().outcome, record(Operation::Get, top));
    assert!(names.release(id, peer, 0));
    assert_eq!(
        names.slot(peer, 0).unwrap().watermark,
        Some(GENERATION_LIMIT - 1)
    );
    assert_eq!(names.census().live(), u32::from(last));
    assert_eq!(
        names.admit(peer, wire(0, GENERATION_LIMIT), unbuilt).err(),
        Some(Refusal::Exhausted)
    );
}

/// A PUT's refusal settled on a free binding turns away a GET at that
/// generation as another operation's, and the PUT retransmission routes to
/// the refusal; retaining a GET's row on a later GET of the same slot routes
/// that generation's PUT frames away in turn.
#[test]
fn a_settled_put_refusal_and_a_retained_get_row_each_refuse_the_other_operation() {
    let mut names = namespace();
    let peer = PeerId(0);
    let refused = wire(2, 7);
    names.settle(peer, refused, Some(row(Operation::Put, refused, 10)));
    assert!(matches!(
        names.route(peer, refused, Operation::Get),
        Route::WrongOperation
    ));
    assert!(matches!(
        names.route(peer, refused, Operation::Put),
        Route::Same {
            active: None,
            cached: Some(_)
        }
    ));
    let next = wire(2, 8);
    let id = names
        .admit(peer, next, || record(Operation::Get, next))
        .unwrap();
    names.retain(peer, 2, id, row(Operation::Get, next, 10));
    assert!(names.release(id, peer, 2));
    assert!(matches!(
        names.route(peer, next, Operation::Put),
        Route::WrongOperation
    ));
    assert!(matches!(
        names.route(peer, next, Operation::Get),
        Route::Same {
            active: None,
            cached: Some(_)
        }
    ));
    assert_eq!(names.wrong_operation(), 2);
}
