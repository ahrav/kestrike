//! PUT permission against a key ring of two principals: the grant names exactly the configured peers, every refusal at load leaves the budget unchanged, and the check refuses every other peer.

use crate::storage::EngineBudget;

use super::auth::{KeyEntry, KeyError, KeyRing};
use super::datagram::PeerId;
use super::frame::Status;
use super::permit::PutPermits;

const CLIENT: u32 = 0x0000_0C11;
const OTHER: u32 = 0x0000_0C22;

/// A ring over `CLIENT` then `OTHER`, so a grant indexed by its list position instead of by peer would name the wrong peer.
fn ring() -> KeyRing {
    KeyRing::load(
        &[CLIENT, OTHER],
        &[
            KeyEntry {
                principal: CLIENT,
                key: &[0x11; 32],
            },
            KeyEntry {
                principal: OTHER,
                key: &[0x22; 32],
            },
        ],
        1,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap()
}

/// PUT permission grants exactly the configured principals of the ring and nothing else; a grant naming an unknown principal or one principal twice refuses at load with the budget unchanged, and the check refuses every other peer with `PermissionDenied`.
#[test]
fn put_permission_grants_exactly_the_configured_peers() {
    let owner_ring = ring();
    let mut budget = EngineBudget::new(1 << 20);
    let permits = PutPermits::load(&owner_ring, &[OTHER], &mut budget).unwrap();
    assert_eq!(budget.used(), PutPermits::charge(2));
    let other = owner_ring.peer_of(OTHER).unwrap();
    let client = owner_ring.peer_of(CLIENT).unwrap();
    assert_eq!(permits.check(other), Ok(()));
    assert_eq!(permits.check(client), Err(Status::PermissionDenied));
    assert_eq!(permits.check(PeerId(2)), Err(Status::PermissionDenied));
    let none = PutPermits::load(&owner_ring, &[], &mut budget).unwrap();
    assert_eq!(none.check(other), Err(Status::PermissionDenied));
    for (granted, refusal) in [
        (&[0x0BAD][..], KeyError::Unknown { principal: 0x0BAD }),
        (
            &[CLIENT, OTHER, CLIENT][..],
            KeyError::Duplicate { principal: CLIENT },
        ),
    ] {
        let mut budget = EngineBudget::new(1 << 20);
        assert_eq!(
            PutPermits::load(&owner_ring, granted, &mut budget).err(),
            Some(refusal)
        );
        assert_eq!(budget.used(), 0);
    }
    let mut tight = EngineBudget::new(1);
    assert!(matches!(
        PutPermits::load(&owner_ring, &[], &mut tight),
        Err(KeyError::Budget(_))
    ));
    assert_eq!(tight.used(), 0);
}
