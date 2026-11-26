//! Custody histories over the composed endpoint of `composed_tests`: a reset
//! beside a held chain and a held read, a close beside the same holds with
//! its terminals in both orders, and a session replacement with an
//! application-held fragment, a held read and a device-held chain. Each
//! history checks exact payload bytes against the independent object, the
//! custody of each identity through the census, the pool reports, the
//! extent ledger and the client's reserved count, and the drain of live
//! attributable resources within its own declared bound.

use crate::storage::owner_fixture::storage;
use crate::storage::{Crc32c, PoolKind};

use super::composed_tests::{Composed, composed};
use super::fetch::Outcome;
use super::frame::{Kind, Status, parse};
use super::owner_tests::{collect, key, payload};
use super::requests::RequestId;
use crate::native::Link;

/// Turns one history grants a healthy owner, client and device to finish a
/// GET or a drain once every hold ended.
const HEALTHY: u64 = 400;

/// Turns one history grants a drain whose last hold just ended.
const DRAIN: u64 = 40;

/// The deadline of a GET a close cuts short, and the turns the client is
/// granted to give up on it.
const CLIENT_DEADLINE_US: u64 = 2_000_000;
const CLIENT_GIVES_UP: u64 = CLIENT_DEADLINE_US / 100 + HEALTHY;

impl Composed<'_> {
    fn get(&mut self, name: u8) -> RequestId {
        self.get_within(name, 30_000_000)
    }

    /// A GET of `name` the client abandons `deadline_us` after now.
    fn get_within(&mut self, name: u8, deadline_us: u64) -> RequestId {
        self.client
            .get(key(name), 0, 1 << 20, self.turn * 100, deadline_us)
            .unwrap()
    }

    /// A GET of `name` with the device's returns withheld, the bridge tapped
    /// and a hold armed on its second read.
    fn arm_held_get(&mut self, name: u8, deadline_us: u64) -> RequestId {
        self.withhold_returns();
        self.tap();
        self.arm_read_hold(1);
        self.get_within(name, deadline_us)
    }

    /// An armed GET of `name` driven until the device holds a DATA chain of
    /// it and its second read is held before its tick, with every accepted
    /// chain carried; returns the request, the held read's token and the
    /// bytes delivered so far.
    fn held_get(
        &mut self,
        name: u8,
        deadline_us: u64,
    ) -> (RequestId, crate::storage::CommandToken, Vec<u8>) {
        let id = self.arm_held_get(name, deadline_us);
        let mut bytes = Vec::new();
        for _ in 0..HEALTHY {
            collect(&mut self.client, id, &mut bytes);
            if self.held_read().is_some() && self.carried_any(data_of(id)) {
                break;
            }
            self.turn();
        }
        let token = self.held_read().expect("the second read is held");
        assert!(self.carried_any(data_of(id)), "a DATA chain was carried");
        assert!(self.chains_held() > 0, "the device holds the DATA chain");
        self.outbound();
        self.tapped();
        collect(&mut self.client, id, &mut bytes);
        (id, token, bytes)
    }

    /// Drives the GET `id` to its outcome within `bound` turns, collecting
    /// its bytes into `bytes`.
    fn finish(&mut self, id: RequestId, bytes: &mut Vec<u8>, bound: u64) -> Option<Outcome> {
        for _ in 0..bound {
            collect(&mut self.client, id, bytes);
            if self.client.outcome(id).is_some() {
                break;
            }
            self.turn();
        }
        collect(&mut self.client, id, bytes);
        self.client.outcome(id)
    }

    /// Live resources the owner and device still attribute to requests: the
    /// owner's live requests, the chains the device holds and the read
    /// sources out of their pool.
    fn live(&self) -> (u32, u32, u32) {
        (self.census().live(), self.chains_held(), self.sources_out())
    }

    /// Read-response sources out of their pool: held by a read, a chain or
    /// a quarantined command.
    fn sources_out(&self) -> u32 {
        self.out(PoolKind::ReadResponse)
    }

    /// Ends the hold `end` names: the held read `token` or the device's returns.
    fn end(&mut self, end: Hold, token: crate::storage::CommandToken) {
        match end {
            Hold::Read => self.control.release(token),
            Hold::Nic => self.return_within_turn(),
        }
    }
}

/// A reset announced while the device holds a chain and a read is held:
/// recovery proves the stop, which returns every held chain, and restarts the
/// device, after which the released read lets the GET complete exact within
/// its bound; the owner then closes and drains within its bound.
#[test]
fn a_reset_beside_a_held_chain_and_read_recovers_and_the_get_completes_within_its_bound() {
    let storage = storage(8);
    let object = payload(40_000, 31);
    let mut c = composed(&storage, &[(key(1), 0, &object)], |_| {});
    let before = (c.ledger(&storage), c.client.reserved());
    let (id, token, mut bytes) = c.held_get(1, 30_000_000);
    let (stops, restarts) = (c.port().stops, c.port().restarts);
    c.port().reset = true;
    c.turns_until(DRAIN, |c| c.owner.transport().report().resets > 0);
    let report = c.owner.transport().report();
    assert_eq!(
        (report.resets, report.recoveries, report.restart_error),
        (1, 1, None),
        "one reset recovered in place"
    );
    assert_eq!(
        (c.port().stops, c.port().restarts),
        (stops + 1, restarts + 1),
        "recovery stopped and restarted the device once"
    );
    assert_eq!(c.owner.transport().link(), Link::Up);
    assert_eq!(c.chains_held(), 0, "the proven stop returned every chain");
    assert_eq!(
        c.census().live(),
        1,
        "the GET lives on through the recovery"
    );
    assert_eq!(c.client.outcome(id), None);
    collect(&mut c.client, id, &mut bytes);
    assert!(
        !bytes.is_empty() && bytes == object[..bytes.len()],
        "the prefix delivered before the reset is exact"
    );
    c.return_within_turn();
    c.control.release(token);
    assert_eq!(c.finish(id, &mut bytes, HEALTHY), Some(Outcome::Complete));
    assert_eq!(bytes, object, "the GET read back exact across the reset");
    assert!(c.client.retire(id));
    c.turns_until(DRAIN, |c| c.live() == (0, 0, 0));
    assert_eq!(c.live(), (0, 0, 0), "every live resource drained");
    assert_eq!(
        (c.ledger(&storage), c.client.reserved()),
        before,
        "a read changes no extent and leaves no fragment charged"
    );
    let _ = c.owner.close(c.turn * 100);
    c.turns_until(DRAIN, |c| c.owner.blockers().is_none());
    assert_eq!(
        c.owner.blockers(),
        None,
        "the owner drained within its bound"
    );
    assert_eq!(c.carried, c.owner.transport().report().sent);
}

/// Whether a datagram is a DATA frame of request `id`.
fn data_of(id: RequestId) -> impl Fn(&[u8]) -> bool {
    move |datagram| {
        parse(Crc32c::detect(), datagram, false).is_ok_and(|frame| {
            (frame.header().kind, frame.header().request) == (Kind::Data, id.wire())
        })
    }
}

/// A hold a closed owner's request drains behind: its held read or the
/// chain the device holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
    Read,
    Nic,
}

impl Hold {
    fn partner(self) -> Self {
        match self {
            Self::Read => Self::Nic,
            Self::Nic => Self::Read,
        }
    }
}

/// A close while the device holds a chain and a read is held: the close ends
/// payload, keeps custody with the held read and the held chain, and permits
/// their terminals in either order; the owner drains within its bound once
/// both ended.
fn late_read_close(first: Hold) {
    let storage = storage(8);
    let object = payload(40_000, 32);
    let mut c = composed(&storage, &[(key(1), 0, &object)], |_| {});
    let before = (c.ledger(&storage), c.client.reserved());
    let (id, token, mut bytes) = c.held_get(1, CLIENT_DEADLINE_US);
    let held = c.chains_held();
    let sources = c.sources_out();
    let progress = c.owner.close(c.turn * 100);
    assert!(
        !matches!(progress, crate::storage::QuiesceProgress::Quiesced(_)),
        "the held read keeps the device busy: {progress:?}"
    );
    let sent = c.owner.transport().report().sent;
    c.tap();
    c.turns(DRAIN);
    collect(&mut c.client, id, &mut bytes);
    assert!(
        !c.carried_any(data_of(id)),
        "the close ended payload: the device carried no DATA after it"
    );
    assert_eq!(c.owner.transport().report().sent, sent);
    assert!(
        bytes == object[..bytes.len()],
        "the delivered prefix is exact"
    );
    let delivered = bytes.len();
    assert!(
        delivered > 0,
        "a prefix reached the client before the close"
    );
    assert_eq!(
        c.chains_held(),
        held,
        "the held chain stays with the device"
    );
    assert_eq!(
        c.sources_out(),
        sources,
        "the held read's and chains' sources stay out"
    );
    assert_eq!(
        c.arena.report(PoolKind::ReadResponse).quarantined,
        1,
        "the close cancelled the held read, whose command the volume quarantines"
    );
    assert_eq!(c.census().live(), 1, "the request drains behind its holds");
    assert!(c.owner.blockers().is_some());
    c.end(first, token);
    c.turns(DRAIN);
    assert_eq!(c.census().live(), 1, "the other hold keeps custody");
    assert!(
        c.owner.blockers().is_some(),
        "the close waits on {:?}",
        first.partner()
    );
    let chains = match first {
        Hold::Read => held,
        Hold::Nic => 0,
    };
    assert_eq!(c.chains_held(), chains, "{first:?} ended first");
    c.end(first.partner(), token);
    c.turns(DRAIN);
    assert_eq!(c.live(), (0, 0, 0), "both terminals drained the request");
    assert_eq!(
        c.owner.blockers(),
        None,
        "the owner drained within its bound"
    );
    // The client gives the GET up at its deadline, short of Complete, with
    // exactly the prefix the owner handed it before the close.
    let outcome = c.finish(id, &mut bytes, CLIENT_GIVES_UP);
    assert!(
        matches!(outcome, Some(Outcome::Incomplete(_) | Outcome::Failed(_))),
        "the GET ends short of Complete after its accepted prefix: {outcome:?}"
    );
    assert_eq!(bytes.len(), delivered, "payload ended at the close");
    assert!(!c.carried_any(data_of(id)));
    assert!(bytes == object[..bytes.len()]);
    assert!(c.client.retire(id));
    assert_eq!(
        (c.ledger(&storage), c.client.reserved()),
        before,
        "a read changes no extent and leaves no fragment charged"
    );
}

#[test]
fn a_late_read_close_drains_once_the_read_returns_and_then_the_device() {
    late_read_close(Hold::Read);
}

#[test]
fn a_late_read_close_drains_once_the_device_returns_and_then_the_read() {
    late_read_close(Hold::Nic);
}

/// A session replacement while the application holds a fragment of a GET,
/// the device holds its later read and the device holds its sent chain: the
/// replaced request ends short and drains behind its own read and chain
/// custody; a successor on the same key completes exact beside it, and a
/// redelivered stale DATA reaches no request; the old custody ends through
/// its own read return and chain return, charging the old request alone;
/// the old fragment keeps its bytes until its drop, which releases one
/// orphan charge and grants the slot's new request nothing.
#[test]
fn a_replacement_over_the_device_isolates_the_successor_from_the_old_fragment_read_and_chain() {
    let storage = storage(8);
    let object = payload(40_000, 33);
    let mut c = composed(&storage, &[(key(1), 0, &object)], |_| {});
    let before = (c.ledger(&storage), c.client.reserved());
    let replaced = c.arm_held_get(1, 30_000_000);
    let mut fragment = None;
    for _ in 0..HEALTHY {
        if fragment.is_none() {
            fragment = c.client.take(replaced);
        }
        if fragment.is_some() && c.held_read().is_some() {
            break;
        }
        c.turn();
    }
    let fragment = fragment.expect("the first fragment");
    let first = fragment.bytes().to_vec();
    assert_eq!(&object[..first.len()], &first[..]);
    let token = c.held_read().expect("the second read is held");
    assert!(c.chains_held() > 0, "the device holds a sent chain");
    let stale = c
        .tapped()
        .into_iter()
        .find(|datagram| data_of(replaced)(datagram))
        .expect("a DATA of the old session was carried");
    let mut taken = first.clone();
    collect(&mut c.client, replaced, &mut taken);
    assert!(
        taken == object[..taken.len()],
        "the bytes handed out are exact"
    );
    let reserved = c.client.reserved();
    let held = (c.chains_held(), c.sources_out());
    assert!(
        held.0 > 0 && held.1 == 2,
        "the fragment, the read and the chain are held at once: the chain's and the read's sources are out"
    );
    // The replacement ends the old request's logical work and keeps its custody.
    c.client.session(c.turn * 100);
    c.turns_until(HEALTHY, |c| {
        c.client.state() == super::client::SessionState::Active
    });
    assert_eq!(c.client.state(), super::client::SessionState::Active);
    assert!(
        c.chains_held() >= held.0 && c.sources_out() == held.1,
        "the old chain and both sources stay out through the replacement, whose handshake chains join the held ones: {:?}",
        (c.chains_held(), c.sources_out())
    );
    assert_eq!(
        c.client.outcome(replaced),
        Some(Outcome::Incomplete(Status::SessionMismatch)),
        "the replaced request ends short after the bytes it handed out"
    );
    assert_eq!(c.census().active, 0, "the replaced request ended");
    assert_eq!(
        c.census().draining,
        1,
        "the held read and chain keep its slot and share"
    );
    assert_eq!(
        fragment.bytes(),
        &first[..],
        "the held fragment keeps its bytes"
    );
    assert_eq!(
        c.client.reserved(),
        reserved,
        "the replacement charges nothing new"
    );
    // The successor is admitted and served beside the draining custody, with
    // the device returning its chains within a turn.
    c.return_within_turn();
    let successor = c.get(1);
    assert_ne!(
        successor.slot(),
        replaced.slot(),
        "the draining slot stays bound"
    );
    let dropped = c.client.fetch_report().dropped;
    let mismatched = c.client.session_report().mismatched;
    c.net.borrow_mut().inject(0, &stale);
    let mut bytes = Vec::new();
    assert_eq!(
        c.finish(successor, &mut bytes, HEALTHY),
        Some(Outcome::Complete)
    );
    assert_eq!(bytes, object, "the successor returns its own bytes");
    assert_eq!(
        (
            c.client.session_report().mismatched,
            c.client.fetch_report().dropped
        ),
        (mismatched + 1, dropped),
        "the stale DATA arrived and ended at the session layer"
    );
    c.turns_until(DRAIN, |c| c.census().active == 0 && c.chains_held() == 0);
    c.turns(DRAIN);
    assert_eq!(
        (c.census().active, c.census().draining, c.chains_held()),
        (0, 1, 0),
        "the device returned every chain, the old request's with the successor's; the old read keeps the old request draining through the bound"
    );
    // The device returns the old read: the old custody ends and the old
    // request leaves, with the successor's outcome and bytes untouched.
    c.control.release(token);
    c.turns(DRAIN);
    assert_eq!(c.live(), (0, 0, 0), "the old custody drained");
    assert_eq!(c.client.outcome(successor), Some(Outcome::Complete));
    assert_eq!(fragment.bytes(), &first[..]);
    // The old request retires with its fragment out; a later request takes
    // its slot; the fragment's drop then frees the old request's one orphan
    // charge and grants the slot's new request nothing.
    assert!(c.client.retire(replaced));
    let later = c.get(1);
    assert_eq!(later.slot(), replaced.slot(), "the freed slot is reused");
    let charged = c.client.reserved();
    drop(fragment);
    assert_eq!(
        c.client.reserved(),
        charged - 1,
        "the drop releases one orphan charge"
    );
    let mut bytes = Vec::new();
    assert_eq!(
        c.finish(later, &mut bytes, HEALTHY),
        Some(Outcome::Complete)
    );
    assert_eq!(
        bytes, object,
        "the slot's new request returns its own bytes"
    );
    assert!(c.client.retire(successor) && c.client.retire(later));
    c.turns_until(DRAIN, |c| c.live() == (0, 0, 0));
    assert_eq!(c.live(), (0, 0, 0));
    assert_eq!(
        (c.ledger(&storage), c.client.reserved()),
        before,
        "reads change no extent, and every fragment charge returned"
    );
}

/// The fixture's one finite construction budget: the wire's and the burst
/// logic's charges equal the charges they declare and the bytes they
/// allocated, which also pins both constructors to their retained
/// allocations alone, and the owner's charge bounds the bytes it allocated.
#[test]
fn construction_charges_are_each_parts_declared_charge_and_bound_its_allocation() {
    let storage = storage(8);
    let c = composed(&storage, &[], |_| {});
    let [
        (wire, wire_allocated),
        (burst, burst_allocated),
        (owner, owner_allocated),
    ] = c.charges;
    assert_eq!(Some(wire), crate::native::Wire::charge(1));
    assert_eq!(
        Some(burst),
        crate::native::Burst::<crate::native::mock::MockPort>::charge(8, 1, 8)
    );
    assert_eq!(
        (wire, burst),
        (wire_allocated, burst_allocated),
        "each charge is the bytes its part allocated"
    );
    assert!(
        owner_allocated > 0 && owner_allocated <= owner,
        "the owner's charge {owner} bounds its allocation {owner_allocated}"
    );
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_reset_beside_a_held_chain_and_read_recovers_and_the_get_completes_within_its_bound,
    a_late_read_close_drains_once_the_read_returns_and_then_the_device,
    a_late_read_close_drains_once_the_device_returns_and_then_the_read,
    a_replacement_over_the_device_isolates_the_successor_from_the_old_fragment_read_and_chain,
);
