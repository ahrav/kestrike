//! Client operations share a generation counter and wire-slot cap; refused admissions preserve namespace state.

use crate::storage::EngineBudget;

use super::client_namespace::{ClientNamespace, ClientRecord, IdentityPressure};
use super::datagram::PeerId;
use super::fetch::{FetchCoreError, Releases};
use super::namespace::{Operated, Operation};
use super::requests::{RequestCensus, RequestId, RequestPressure, RequestTable};

struct Record {
    operation: Operation,
    peer: PeerId,
    wire: u64,
}

impl Operated for Record {
    fn operation(&self) -> Operation {
        self.operation
    }
}

impl ClientRecord for Record {
    fn peer(&self) -> PeerId {
        self.peer
    }

    fn wire(&self) -> u64 {
        self.wire
    }

    fn handed(&self) -> u32 {
        0
    }
}

fn namespace<'p>(
    releases: &'p Releases,
    table: RequestTable<Record>,
) -> ClientNamespace<'p, Record> {
    ClientNamespace::new(table, releases, &mut EngineBudget::new(1 << 20)).unwrap()
}

fn admit(
    requests: &mut ClientNamespace<'_, Record>,
    operation: Operation,
    peer: PeerId,
    cap: u32,
) -> Result<(RequestId, u64), IdentityPressure> {
    let mut issued = None;
    let id = requests.admit(peer, cap, |wire| {
        issued = Some(wire);
        Record {
            operation,
            peer,
            wire,
        }
    })?;
    Ok((id, issued.expect("admission builds the record")))
}

fn census(requests: &ClientNamespace<'_, Record>) -> RequestCensus {
    requests.table().census()
}

#[test]
fn operations_share_the_slot_cap_and_the_generation_counter() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = namespace(&releases, RequestTable::new(4, 1, 4));
    let peer = PeerId(0);
    let (get, get_wire) = admit(&mut requests, Operation::Get, peer, 1).unwrap();
    assert_eq!(RequestId::from_wire(get_wire).slot(), 0);
    let before = census(&requests);
    assert_eq!(
        admit(&mut requests, Operation::Put, peer, 1),
        Err(IdentityPressure::Requests(RequestPressure::Peer)),
        "the live GET holds the only wire slot"
    );
    assert_eq!(census(&requests), before);
    assert_eq!(requests.route(peer, get_wire, Operation::Get), Some(get));
    assert!(requests.release(get));
    let (put, put_wire) = admit(&mut requests, Operation::Put, peer, 1).unwrap();
    assert_eq!(RequestId::from_wire(put_wire).slot(), 0);
    assert_eq!(
        RequestId::from_wire(put_wire).generation(),
        RequestId::from_wire(get_wire).generation() + 1,
        "the cap refusal issued no generation"
    );
    for operation in [Operation::Get, Operation::Put] {
        assert_eq!(
            requests.route(peer, get_wire, operation),
            None,
            "a delayed frame of the GET reaches no request"
        );
    }
    assert_eq!(requests.route(peer, put_wire, Operation::Get), None);
    assert_eq!(requests.route(peer, put_wire, Operation::Put), Some(put));
    assert_eq!(requests.route(PeerId(1), put_wire, Operation::Put), None);
}

#[test]
fn refused_admissions_keep_the_generation_counter() {
    let releases = Releases::with_generation_limit(1, 1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = namespace(&releases, RequestTable::new(1, 2, 1));
    let (first, wire) = admit(&mut requests, Operation::Get, PeerId(0), 1).unwrap();
    assert_eq!(RequestId::from_wire(wire).generation(), 0);
    let before = census(&requests);
    assert_eq!(
        admit(&mut requests, Operation::Put, PeerId(1), 1),
        Err(IdentityPressure::Requests(RequestPressure::Table))
    );
    assert_eq!(census(&requests), before);
    assert!(requests.release(first));
    let (second, wire) = admit(&mut requests, Operation::Put, PeerId(1), 1).unwrap();
    assert_eq!(
        RequestId::from_wire(wire).generation(),
        1,
        "the table refusal kept generation 1 for the next admission"
    );
    assert!(requests.release(second));
    let before = census(&requests);
    assert_eq!(
        admit(&mut requests, Operation::Get, PeerId(0), 1),
        Err(IdentityPressure::Generations)
    );
    assert_eq!(census(&requests), before);
    assert_eq!(before.live(), 0);
}

#[test]
fn a_successor_namespace_continues_the_board() {
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut first = namespace(&releases, RequestTable::new(2, 1, 2));
    let (_, wire) = admit(&mut first, Operation::Get, PeerId(0), 2).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let refused =
        ClientNamespace::<Record>::new(RequestTable::new(2, 1, 2), &releases, &mut budget);
    assert!(matches!(refused, Err(FetchCoreError::BoardInUse)));
    assert_eq!(budget, EngineBudget::new(1 << 20));
    drop(first);
    let mut second = namespace(&releases, RequestTable::new(2, 1, 2));
    let (_, next) = admit(&mut second, Operation::Put, PeerId(0), 2).unwrap();
    assert!(RequestId::from_wire(next).generation() > RequestId::from_wire(wire).generation());
}

#[test]
fn routing_requires_the_admitting_peer() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = namespace(&releases, RequestTable::new(4, 2, 2));
    let (id, wire) = admit(&mut requests, Operation::Get, PeerId(0), 2).unwrap();
    assert_eq!(requests.route(PeerId(0), wire, Operation::Get), Some(id));
    assert_eq!(requests.route(PeerId(1), wire, Operation::Get), None);
}

#[test]
fn wire_slots_past_one_word_go_lowest_first_below_the_cap() {
    let releases = Releases::new(130, &mut EngineBudget::new(1 << 22)).unwrap();
    let mut requests = namespace(&releases, RequestTable::new(130, 1, 130));
    let peer = PeerId(0);
    let ids: Vec<_> = (0..130)
        .map(|slot| {
            let (id, wire) = admit(&mut requests, Operation::Get, peer, 130).unwrap();
            assert_eq!(RequestId::from_wire(wire).slot(), slot);
            id
        })
        .collect();
    let full = Err(IdentityPressure::Requests(RequestPressure::Peer));
    assert_eq!(admit(&mut requests, Operation::Get, peer, 130), full);
    assert!(requests.release(ids[70]));
    assert_eq!(
        admit(&mut requests, Operation::Put, peer, 64),
        full,
        "every wire slot below the cap is held"
    );
    let (_, wire) = admit(&mut requests, Operation::Put, peer, 130).unwrap();
    assert_eq!(RequestId::from_wire(wire).slot(), 70);
    assert_eq!(
        admit(&mut requests, Operation::Get, PeerId(1), 130),
        full,
        "a peer outside the table has no wire slot"
    );
}

#[test]
fn an_exhausted_generation_refuses_before_a_full_table_or_wire_slot() {
    let releases = Releases::with_generation_limit(1, 0, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = namespace(&releases, RequestTable::new(1, 1, 1));
    let (_, wire) = admit(&mut requests, Operation::Put, PeerId(0), 1).unwrap();
    assert_eq!(RequestId::from_wire(wire).generation(), 0);
    let before = census(&requests);
    assert_eq!(before.live(), 1, "the upload holds the table's one slot");
    for operation in [Operation::Get, Operation::Put] {
        assert_eq!(
            admit(&mut requests, operation, PeerId(0), 1),
            Err(IdentityPressure::Generations),
            "{operation:?}"
        );
        assert_eq!(census(&requests), before);
    }
}
