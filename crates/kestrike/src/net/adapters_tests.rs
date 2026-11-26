//! Fragment rows record the upload attempt's owner's validations, after the
//! receipt granting each fragment and before the receipt acknowledging it.

use crate::oracle::{ActionKind, Label, Obligation, Recorder, Serial, check};

use super::adapters::{Attempt, FRAGMENT, LEN, drive, get, owner_validated, tenures, upload};
use super::owner::OwnerConfig;
use super::owner_tests::{OWNER, PRINCIPALS};
use super::put::PutConfig;
use super::put_tests::{scene, scene_with, scene_with_one_serial_in_two_shards};
use super::upload::UploadOutcome;

/// `window` counts fragments.
fn windowed(window: u32) -> OwnerConfig {
    OwnerConfig {
        put: PutConfig {
            window,
            ..OWNER.put
        },
        ..OWNER
    }
}

fn validated(rec: &Recorder) -> usize {
    let fragment = |r: &&crate::oracle::Row| r.kind == ActionKind::Fragment;
    rec.rows().iter().filter(fragment).count()
}

fn passes(rec: Recorder, context: &str) {
    let verdict = check(&rec.finish());
    let judged = [
        Obligation::History,
        Obligation::Bytes,
        Obligation::Custody,
        Obligation::Resources,
    ];
    assert!(verdict.satisfies(&judged), "{context}: {verdict:?}");
}

/// A fragment row validated under an ACK grant follows that ACK's receipt
/// and precedes the receipt that counts the fragment.
#[test]
fn a_flow_controlled_live_upload_passes_the_shared_oracle() {
    for window in [1, 2] {
        scene_with(windowed(window), &PRINCIPALS, |mut scene| {
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 600);
            assert_eq!(
                attempt.outcome,
                Some(UploadOutcome::Published),
                "window {window}"
            );
            let grants: Vec<u32> = rec
                .rows()
                .iter()
                .filter(|r| matches!(r.kind, ActionKind::Ready | ActionKind::Ack))
                .filter_map(|r| r.grant)
                .collect();
            assert_eq!(grants.first(), Some(&window), "READY grants the window");
            assert_eq!(grants.last(), Some(&3), "a later ACK grants the rest");
            assert_eq!(validated(&rec), 3);
            get(&mut scene, &mut rec, 6, Label(1));
            passes(rec, &format!("window {window}"));
        });
    }
}

/// Several client polls between two observations hide which receipt
/// granted a fragment, so the adapter refuses to order the rows.
#[test]
#[should_panic(expected = "more than one client poll ran since the last observation")]
fn a_flow_controlled_upload_observed_across_several_polls_is_refused() {
    scene_with(windowed(1), &PRINCIPALS, |mut scene| {
        let mut rec = Recorder::new(1);
        let mut tenures = tenures(&scene);
        let mut attempt = Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
        for index in 0..3 {
            assert!(attempt.supply(&mut scene, &mut rec, index));
        }
        drive(&mut scene, 40);
        attempt.observe(&scene, &mut rec);
    });
}

#[test]
fn an_attempt_records_only_the_fragments_its_own_owner_validated() {
    scene(&PRINCIPALS, |mut recorded| {
        scene(&PRINCIPALS, |mut other| {
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&recorded);
            let mut attempt =
                Attempt::begin(&mut recorded, &mut rec, (6, Label(1)), LEN, &mut tenures);
            let object = attempt.object.clone();
            let id = upload(&mut other, 6, &object, 30_000_000);
            assert_eq!(
                other.clients[0].put_wire(id),
                recorded.clients[0].put_wire(attempt.id),
                "both owners' uploads of the key carry one wire request ID"
            );
            let mut pieces = object.chunks(FRAGMENT).zip(0..).peekable();
            for _ in 0..600 {
                while let Some(&(piece, index)) = pieces.peek()
                    && other.clients[0].supply(id, index, piece).is_ok()
                {
                    pieces.next();
                }
                drive(&mut other, 1);
                if other.clients[0].put_outcome(id).is_some() {
                    break;
                }
            }
            assert_eq!(
                other.clients[0].put_outcome(id),
                Some(UploadOutcome::Published),
                "the other scene's owner validated every fragment"
            );
            attempt.run(&mut recorded, &mut rec, 600);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            assert_eq!(validated(&rec), 3);
            get(&mut recorded, &mut rec, 6, Label(1));
            passes(rec, "the recorded attempt");
        });
    });
}

/// Fill serials are shard-local; the adapter reads a fill's validations by
/// key and serial, so fills with equal serials each read their own.
#[test]
fn fills_under_one_serial_in_two_shards_read_their_own_validations() {
    scene_with_one_serial_in_two_shards(|scene, fills| {
        for (name, serial) in fills {
            let fill = (name, Serial::new(serial).unwrap());
            assert_eq!(
                owner_validated(&scene, fill, 0),
                (vec![0], 1),
                "key {name} under serial {serial}"
            );
        }
    });
}
