//! The source buffers of a closed client that a link's device still reads.
//!
//! A client whose source slots are buffers of an arena publishes a one-fragment upload over a link
//! that withholds its device returns, and is then closed. The close drops the client's source slots
//! and hands the transport back while the link still reads the sent fragment's buffer, so that
//! buffer must stay off the arena's free stack, counted as held by the device, until the link
//! returns its reference; every other source buffer is free at once. The second test runs the same
//! upload over a link that returns each reference at delivery, and there the close frees every
//! source buffer.
//!
//! Each test reads what the scene did into a value, lets the scene go, and asserts afterwards, so a
//! failure ends in the test's own result line.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::storage::PoolKind;

use super::adapters::{FRAGMENT, drive, upload};
use super::link::TxRelease;
use super::owner_tests::{PRINCIPALS, payload};
use super::put_tests::{Scene, scene};
use super::upload::UploadOutcome;

/// Microseconds the upload may take.
const WAIT_US: u64 = 30_000_000;

/// Turns the upload gets to publish its one fragment.
const TURNS: u64 = 400;

/// The source pool as the arena reports it, and the device references the link holds, at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Custody {
    /// Source buffers on the arena's free stack.
    free: u32,
    /// Source buffers whose handle dropped while a device still reads them.
    device_held: u32,
    /// Device references the link holds.
    link: usize,
}

/// What one upload, the client's close and the link's return of its references did.
#[derive(Debug)]
struct Observed {
    outcome: Option<UploadOutcome>,
    /// Buffers of the source pool.
    count: u32,
    /// Source slots of the live client that still hold a fragment.
    slots_held: usize,
    before_close: Custody,
    after_close: Custody,
    /// Whether the link returned its references without a panic.
    returned: bool,
    after_return: Custody,
}

/// Publishes a one-fragment upload from client 0 over a link whose device returns follow `release`, closes
/// the client, then has the link return every reference it still holds.
fn close_after_an_upload(release: TxRelease) -> Observed {
    let mut observed = None;
    scene(&PRINCIPALS, |mut scene: Scene<'_, '_>| {
        let object = payload(FRAGMENT, 41);
        scene.nets[0].borrow_mut().set_tx_release(release);
        let id = upload(&mut scene, 6, &object, WAIT_US);
        let mut supplied = false;
        for _ in 0..TURNS {
            supplied = supplied || scene.clients[0].supply(id, 0, &object).is_ok();
            drive(&mut scene, 1);
            if scene.clients[0].put_outcome(id).is_some() {
                break;
            }
        }
        // One more turn reclaims what the device returned at delivery.
        drive(&mut scene, 1);
        let outcome = scene.clients[0].put_outcome(id);
        let slots_held = scene.clients[0]
            .sources()
            .iter()
            .filter(|slot| slot.piece().is_some())
            .count();

        let now_us = scene.turn * 100;
        let (net, sourcing) = (scene.nets[0].clone(), scene.sourcing);
        let custody = || {
            let report = sourcing.report(PoolKind::ReadResponse);
            Custody {
                free: report.free,
                device_held: report.nic_held,
                link: net.borrow().nic_held(),
            }
        };
        let count = sourcing.report(PoolKind::ReadResponse).count;
        let before_close = custody();

        let [client, _other] = scene.clients;
        let (_report, transport) = client.close(now_us);
        let after_close = custody();

        // A return that finds no device reference on its buffer panics in a debug build; reading that as a
        // value leaves the verdict to the assertions on the custody the close left.
        let returned = catch_unwind(AssertUnwindSafe(|| net.borrow_mut().release_tx())).is_ok();
        let after_return = custody();
        drop(transport);
        observed = Some(Observed {
            outcome,
            count,
            slots_held,
            before_close,
            after_close,
            returned,
            after_return,
        });
    });
    observed.expect("premise: the scene ran its body")
}

/// Closing the client hands its transport back with device references still held, so the buffer the
/// device still reads stays off the arena's free stack until the device returns it.
#[test]
fn a_closed_clients_device_read_source_stays_off_the_free_stack_until_the_device_returns_it() {
    let seen = close_after_an_upload(TxRelease::Withheld);
    assert_eq!(
        (seen.outcome, seen.slots_held, seen.before_close.link),
        (Some(UploadOutcome::Published), 1, 1),
        "premise: the upload published and the link withholds the one fragment's reference: {seen:?}"
    );
    assert_eq!(
        (seen.before_close.free, seen.before_close.device_held),
        (0, 0),
        "premise: the live client's slots hold every source buffer: {seen:?}"
    );
    assert_eq!(
        seen.after_close,
        Custody {
            free: seen.count - 1,
            device_held: 1,
            link: 1,
        },
        "the close frees every source buffer but the one the device still reads, and returns no reference"
    );
    assert!(
        seen.returned,
        "the link's return finds its reference on the buffer"
    );
    assert_eq!(
        seen.after_return,
        Custody {
            free: seen.count,
            device_held: 0,
            link: 0,
        },
        "the device's return puts the last source buffer on the free stack"
    );
}

/// The same upload over a link that returns each reference at delivery: no device reads a source buffer at
/// the close, so the close alone frees every one.
#[test]
fn a_closed_clients_sources_free_at_the_close_when_the_device_returned_them() {
    let seen = close_after_an_upload(TxRelease::AtDelivery);
    assert_eq!(
        (seen.outcome, seen.slots_held, seen.before_close.link),
        (Some(UploadOutcome::Published), 0, 0),
        "premise: the upload published and the device returned the fragment's reference: {seen:?}"
    );
    let all_free = Custody {
        free: seen.count,
        device_held: 0,
        link: 0,
    };
    assert_eq!(
        seen.after_close, all_free,
        "the close frees every source buffer"
    );
    assert!(seen.returned, "the link has no reference to return");
    assert_eq!(seen.after_return, all_free);
}
