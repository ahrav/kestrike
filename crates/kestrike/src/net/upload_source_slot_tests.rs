//! A held slot frees only once its upload's retention ended and no device reads its buffer: when the later
//! of the two ends. A one-fragment upload runs to publication in the net scene, and the tests read the custody
//! of the client's source slots turn by turn, in both orders of the two ends:
//!
//! - Retention ends first. The client's link withholds its transmit references, so the owner's receipt passes
//!   the fragment and the upload publishes while the NIC still reads the DATA frame's source. The slot must keep
//!   its piece and its bytes, `retire` must refuse, and the device's return must free the slot.
//! - The device's read ends first. The link returns each reference at delivery, before the owner's receipt
//!   passes the fragment. The slot retains its piece and bytes on every undecided turn whose receipt base is 0
//!   and is free on every undecided turn whose receipt base is 1, so the receipt frees the slot before the
//!   outcome is known.
//!
//! Each test records what it sees at every step and asserts after the scene has ended, so a failure ends in the
//! test's own result line with every fixture already dropped.

use super::adapters::{FRAGMENT, drive, upload};
use super::link::TxRelease;
use super::owner_tests::{PRINCIPALS, payload};
use super::put_tests::{Scene, scene};
use super::upload::UploadOutcome;

/// The most turns the scenario waits for the upload's outcome.
const TURNS: usize = 400;

/// Each source slot of client 0 that holds a piece: whether a device still reads it, and its bytes.
fn pieces(scene: &Scene<'_, '_>) -> Vec<(bool, Vec<u8>)> {
    scene.clients[0]
        .sources()
        .iter()
        .filter(|slot| slot.piece().is_some())
        .map(|slot| (slot.device_held(), slot.bytes().to_vec()))
        .collect()
}

/// Client 0 after one turn that left the upload undecided.
#[derive(Debug, PartialEq, Eq)]
struct Turn {
    /// The count of fragments the owner's receipt has passed; a slot's retention ends once this exceeds its
    /// fragment's index.
    base: Option<u32>,
    /// For each slot that holds a piece: whether a device still reads it, and the bytes the slot retains.
    pieces: Vec<(bool, Vec<u8>)>,
}

/// What one run of the scenario showed, step by step.
#[derive(Debug, Default, PartialEq, Eq)]
struct Seen {
    supplied: bool,
    /// Every undecided turn, in turn order.
    undecided: Vec<Turn>,
    /// The upload's outcome when the wait ended.
    outcome: Option<UploadOutcome>,
    /// The slots holding a piece after the turn that published the upload: the receipt passed the fragment.
    published: Vec<(bool, Vec<u8>)>,
    /// Whether `retire` released the request right after publication.
    retired_at_publication: bool,
    /// The slots holding a piece after the link returned every reference it held and the client took one turn.
    returned: Vec<(bool, Vec<u8>)>,
    retired_after_return: bool,
}

/// Uploads the one-fragment `object` under `release` until its outcome is decided, then has the link return every
/// reference it holds and gives the client one turn.
fn published_upload(release: TxRelease, object: &[u8]) -> Seen {
    let mut seen = Seen::default();
    scene(&PRINCIPALS, |mut scene| {
        scene.nets[0].borrow_mut().set_tx_release(release);
        let id = upload(&mut scene, 6, object, 30_000_000);
        seen.supplied = scene.clients[0].supply(id, 0, object) == Ok(FRAGMENT);
        for _ in 0..TURNS {
            drive(&mut scene, 1);
            seen.outcome = scene.clients[0].put_outcome(id);
            if seen.outcome.is_some() {
                break;
            }
            seen.undecided.push(Turn {
                base: scene.clients[0].put_receipt(id).map(|(_, base, _)| base),
                pieces: pieces(&scene),
            });
        }
        seen.published = pieces(&scene);
        seen.retired_at_publication = scene.clients[0].retire(id);
        scene.nets[0].borrow_mut().release_tx();
        drive(&mut scene, 1);
        seen.returned = pieces(&scene);
        seen.retired_after_return = seen.retired_at_publication || scene.clients[0].retire(id);
    });
    seen
}

/// Retention ends first: with device returns withheld, the receipt passes the fragment and the upload publishes
/// while the NIC still reads the fragment's source. The slot keeps its piece and the supplied bytes on every turn
/// up to and at publication, `retire` refuses, and the device's return frees the slot and lets the upload retire.
#[test]
fn a_receipted_fragment_keeps_its_slot_until_the_device_returns_it() {
    let object = payload(FRAGMENT, 61);
    let seen = published_upload(TxRelease::Withheld, &object);
    let held = vec![(true, object.clone())];
    assert!(seen.supplied, "the client took the fragment");
    assert_eq!(
        seen.outcome,
        Some(UploadOutcome::Published),
        "the upload published"
    );
    assert!(
        !seen.undecided.is_empty(),
        "the upload took a turn before it published"
    );
    for (at, turn) in seen.undecided.iter().enumerate() {
        assert_eq!(
            turn.pieces, held,
            "turn {at}: the slot the device still reads keeps its piece and the supplied bytes"
        );
    }
    assert_eq!(
        seen.published, held,
        "the receipt passed the fragment, and the slot the device still reads keeps its piece and the supplied bytes"
    );
    assert!(
        !seen.retired_at_publication,
        "retire refuses while the device reads a source of the upload"
    );
    assert_eq!(seen.returned, vec![], "the device's return frees the slot");
    assert!(
        seen.retired_after_return,
        "the upload retires once the device returned its source"
    );
}

/// Delivery ends the device's read. The owner's receipt frees the slot when it passes the fragment, while the
/// upload is still undecided.
#[test]
fn a_returned_fragment_keeps_its_slot_until_the_receipt_passes_it() {
    let object = payload(FRAGMENT, 62);
    let seen = published_upload(TxRelease::AtDelivery, &object);
    assert!(seen.supplied, "the client took the fragment");
    assert_eq!(
        seen.outcome,
        Some(UploadOutcome::Published),
        "the upload published"
    );
    let bases: Vec<Option<u32>> = seen.undecided.iter().map(|turn| turn.base).collect();
    assert!(
        bases.contains(&Some(0)) && bases.contains(&Some(1)),
        "premise: the upload is undecided on a turn before and a turn after the receipt passes the fragment: \
         {bases:?}"
    );
    for (at, turn) in seen.undecided.iter().enumerate() {
        let retained = if turn.base == Some(0) {
            vec![(false, object.clone())]
        } else {
            vec![]
        };
        assert_eq!(
            turn.pieces, retained,
            "turn {at}, receipt base {:?}: the returned fragment keeps its slot and bytes until the receipt \
             passes it, and the receipt frees the slot",
            turn.base
        );
    }
    assert_eq!(
        seen.published,
        vec![],
        "no slot holds a piece once the upload published"
    );
    assert!(
        seen.retired_at_publication,
        "nothing is held, so the published upload retires"
    );
    assert_eq!(seen.returned, vec![], "no slot holds a piece at the end");
}
