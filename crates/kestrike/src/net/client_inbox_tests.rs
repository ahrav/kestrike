//! The client's INVALIDATED inbox over one owner session: `Client::take_invalidated` returns the oldest INVALIDATED
//! received and not yet taken, and the inbox holds `INVALIDATED_INBOX` untaken acknowledgments and drops the next one
//! to arrive.

use crate::net::owner_tests::{PRINCIPALS, key};
use crate::net::put_tests::{Scene, fenced_coverage, scene};
use crate::storage::store::Client as StoreClient;
use crate::storage::store::sim::{MemLog, Shared};
use crate::storage::store_tests::seeded_under;

use super::{INVALIDATED_INBOX, Invalidated};

/// One INVALIDATE of key `name` from client 0, covered by the owner and acknowledged to the client, which polls for
/// the INVALIDATED and leaves its inbox untaken. Returns the acknowledgment that INVALIDATE draws: its request
/// field, key and interval, the value the client's inbox is offered.
fn acknowledge(
    scene: &mut Scene<'_, '_>,
    coverage: &mut StoreClient<Shared, MemLog>,
    name: u8,
) -> Invalidated {
    let request = scene.clients[0].invalidate(key(name), 3, 5).unwrap();
    scene.turns(4);
    let mut acknowledged = Vec::new();
    scene
        .owner
        .cover_pending(coverage, &mut acknowledged, 0)
        .unwrap();
    assert_eq!(
        acknowledged.len(),
        1,
        "the owner covers the INVALIDATE of key {name}"
    );
    scene.turns(4);
    scene.clients[0].poll(scene.turn * 100);
    Invalidated {
        request,
        key: key(name),
        low: 3,
        high: 5,
    }
}

/// Two more acknowledgments than the inbox holds reach one client over one owner session before any take. The drain
/// returns exactly the first `INVALIDATED_INBOX` in arrival order: the inbox kept the oldest and dropped each one that
/// arrived while it was full. An acknowledgment that arrives after the drain is taken, so the full inbox alone
/// dropped the two.
#[test]
fn a_full_inbox_drops_the_next_acknowledgment_and_drains_the_oldest_first() {
    scene(&PRINCIPALS, |mut scene| {
        let store = seeded_under(scene.owner.tenure());
        let (fencing, mut coverage) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let arrived: Vec<Invalidated> = (0..INVALIDATED_INBOX + 2)
            .map(|name| acknowledge(&mut scene, &mut coverage, u8::try_from(name).unwrap()))
            .collect();
        let mut requests: Vec<u64> = arrived.iter().map(|ack| ack.request).collect();
        requests.sort_unstable();
        requests.dedup();
        assert_eq!(
            requests.len(),
            INVALIDATED_INBOX + 2,
            "every acknowledgment carries its own request field"
        );
        let mut drained = Vec::new();
        while let Some(taken) = scene.clients[0].take_invalidated() {
            drained.push(taken);
        }
        assert_eq!(
            drained.len(),
            INVALIDATED_INBOX,
            "the inbox holds INVALIDATED_INBOX untaken acknowledgments and drops the next one to arrive"
        );
        assert_eq!(
            drained,
            arrived[..INVALIDATED_INBOX],
            "the drain is the oldest INVALIDATED_INBOX acknowledgments in arrival order"
        );
        let later = acknowledge(&mut scene, &mut coverage, 200);
        assert_eq!(
            scene.clients[0].take_invalidated(),
            Some(later),
            "an acknowledgment that arrives at a drained inbox is kept"
        );
        assert_eq!(scene.clients[0].take_invalidated(), None);
    });
}

/// Exactly as many acknowledgments as the inbox holds, 64, reach one client before any take. None is dropped: the
/// drain returns all of them in arrival order, and the one that arrives after the drain is taken once.
#[test]
fn an_inbox_filled_to_its_bound_drops_nothing() {
    assert_eq!(INVALIDATED_INBOX, 64, "the inbox holds 64");
    scene(&PRINCIPALS, |mut scene| {
        let store = seeded_under(scene.owner.tenure());
        let (fencing, mut coverage) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let arrived: Vec<Invalidated> = (0..INVALIDATED_INBOX)
            .map(|name| acknowledge(&mut scene, &mut coverage, u8::try_from(name).unwrap()))
            .collect();
        let mut drained = Vec::new();
        while let Some(taken) = scene.clients[0].take_invalidated() {
            drained.push(taken);
        }
        let later = acknowledge(&mut scene, &mut coverage, 200);
        let mut requests: Vec<u64> = (arrived.iter().chain([&later]))
            .map(|ack| ack.request)
            .collect();
        requests.sort_unstable();
        requests.dedup();
        assert_eq!(
            requests.len(),
            INVALIDATED_INBOX + 1,
            "every acknowledgment carries its own request field"
        );
        assert_eq!(
            drained, arrived,
            "a full inbox drains every acknowledgment in arrival order"
        );
        assert_eq!(
            scene.clients[0].take_invalidated(),
            Some(later),
            "an acknowledgment that arrives at a drained inbox is kept"
        );
        assert_eq!(scene.clients[0].take_invalidated(), None);
    });
}
