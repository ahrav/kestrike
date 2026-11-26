//! A retained PUT row that recorded a PREPARE shape answers a PREPARE whose
//! key, serial, metadata length, body length or TTL differs with
//! `ConflictingRequest`, under the row's epoch and before its expiry. The
//! answer leaves the row, the slot's binding, the request census and the PUT
//! occupancy as they were, and the original PREPARE sent afterwards still
//! draws the row's terminal. The three tests take the row of a published
//! upload, of an upload cancelled after its PREPARE, and of a cancelled upload
//! that still drains its held writes under its binding.

use super::datagram::PeerId;
use super::frame::{Header, Kind, Status};
use super::geometry::{FRAGMENT_LEN, FragmentGeometry};
use super::owner::OwnerConfig;
use super::owner_tests::{OWNER, PRINCIPALS, payload};
use super::put_tests::{
    Scene, cancel, error, prepare, request, scene, scene_with, send_all, slot_bound, upload_at,
};
use super::serve::ServeConfig;

/// The key name every upload here writes.
const NAME: u8 = 5;
/// The TTL every original PREPARE here names, equal to the 60,000 ms
/// `upload_at` sends in its PREPARE. The tests also pass it to `upload_at` as
/// the BEGIN's remaining time.
const TTL_MS: u32 = 60_000;

/// What a refused PREPARE must leave alone: peer 1's wire slot 1 with its
/// retained row and binding, the request census and the PUT occupancy.
fn evidence(scene: &Scene<'_, '_>) -> String {
    format!(
        "{:?} {:?} {:?}",
        scene.owner.request_slot(PeerId(1), 1),
        scene.owner.census(),
        scene.owner.put_occupancy(),
    )
}

/// The PREPARE frames that differ from the recorded one of `serial` and
/// `body_len` in one recorded field each, with the field's name. The
/// header's `total` and `count` follow a changed length.
fn changed(
    scene: &mut Scene<'_, '_>,
    at: u64,
    serial: u64,
    body_len: u32,
) -> Vec<(&'static str, Header)> {
    let grown = body_len + 100;
    vec![
        (
            "body length",
            scene.frame(
                1,
                Kind::PutPrepare,
                at,
                NAME,
                prepare(serial, grown, TTL_MS),
            ),
        ),
        (
            "TTL",
            scene.frame(
                1,
                Kind::PutPrepare,
                at,
                NAME,
                prepare(serial, body_len, 2 * TTL_MS),
            ),
        ),
        (
            "serial",
            scene.frame(
                1,
                Kind::PutPrepare,
                at,
                NAME,
                prepare(serial + 1, body_len, TTL_MS),
            ),
        ),
        (
            "metadata length",
            scene.frame(1, Kind::PutPrepare, at, NAME, |header| {
                prepare(serial, body_len, TTL_MS)(header);
                header.metadata_len = 8;
                header.total = u64::from(body_len) + 8;
                header.count = FragmentGeometry::fragments(header.total) as u32;
            }),
        ),
        (
            "key",
            scene.frame(
                1,
                Kind::PutPrepare,
                at,
                NAME + 1,
                prepare(serial, body_len, TTL_MS),
            ),
        ),
    ]
}

/// Sends every changed PREPARE to the retained row and checks that each
/// draws `ConflictingRequest` and leaves all of the evidence as it was, then that
/// the original PREPARE still draws `terminal`.
fn conflicts_keep_the_row(
    scene: &mut Scene<'_, '_>,
    at: u64,
    serial: u64,
    body_len: u32,
    terminal: impl Fn(&Header) -> bool,
    label: &str,
) {
    let before = evidence(scene);
    assert!(
        before.contains("cached: Some"),
        "{label}: the slot retains a row: {before}"
    );
    for (field, header) in changed(scene, at, serial, body_len) {
        let answer = scene.one(1, &header);
        assert_eq!(
            error(&answer),
            Some(Status::ConflictingRequest),
            "{label}: a PREPARE with a changed {field} conflicts: {answer:?}"
        );
        assert_eq!(
            evidence(scene),
            before,
            "{label}: the conflict on the {field} kept the row, binding, census and occupancy"
        );
    }
    let original = scene.frame(
        1,
        Kind::PutPrepare,
        at,
        NAME,
        prepare(serial, body_len, TTL_MS),
    );
    let answer = scene.one(1, &original);
    assert!(
        terminal(&answer),
        "{label}: the matching duplicate recovers the original terminal: {answer:?}"
    );
}

/// The row of a published upload refuses each changed PREPARE and then
/// replays its RESULT to the original one.
#[test]
fn a_changed_prepare_to_a_published_row_conflicts_and_the_result_still_replays() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 71);
        let (at, serial) = upload_at(&mut scene, request(1, 1), &object, TTL_MS);
        send_all(&mut scene, at, serial, &object, 0..2);
        scene.turns(20);
        let replies = scene.replies(1);
        assert!(
            replies.iter().any(|reply| reply.kind == Kind::PutResult),
            "the upload published: {replies:?}"
        );
        assert_eq!(scene.live(), 0);
        assert!(scene.visible(NAME));
        conflicts_keep_the_row(
            &mut scene,
            at,
            serial,
            object.len() as u32,
            |answer| answer.kind == Kind::PutResult && answer.allocation == serial,
            "published",
        );
        assert_eq!(
            scene.live(),
            0,
            "no changed PREPARE re-admitted the attempt"
        );
        assert_eq!(scene.fetch(NAME), object);
    });
}

/// The row of an upload cancelled after its PREPARE recorded a shape refuses
/// each changed PREPARE and then replays `Cancelled` to the original one.
#[test]
fn a_changed_prepare_to_a_failed_row_with_a_shape_conflicts_and_the_error_still_replays() {
    for body_len in [100, 3 * FRAGMENT_LEN] {
        scene(&PRINCIPALS, |mut scene| {
            let object = vec![0; body_len as usize];
            let (at, serial) = upload_at(&mut scene, request(1, 1), &object, TTL_MS);
            let stop = scene.frame(1, Kind::PutCancel, at, NAME, cancel(serial));
            assert_eq!(error(&scene.one(1, &stop)), Some(Status::Cancelled));
            assert_eq!(scene.live(), 0);
            assert!(!slot_bound(&scene, 1), "the sent terminal freed the slot");
            conflicts_keep_the_row(
                &mut scene,
                at,
                serial,
                body_len,
                |answer| error(answer) == Some(Status::Cancelled),
                "failed",
            );
            assert_eq!(
                scene.live(),
                0,
                "no changed PREPARE re-admitted the attempt"
            );
            assert!(!scene.visible(NAME));
        });
    }
}

/// An upload cancelled while its writes are held, whose PUT ERROR a full
/// reply ring dropped, still drains under its binding. Each changed PREPARE
/// draws `ConflictingRequest` and keeps that binding and the draining
/// record; the original PREPARE then replays `Cancelled`, which frees the
/// binding once sent, and the fill drains when its writes return.
#[test]
fn a_changed_prepare_to_a_draining_failed_row_conflicts_and_keeps_the_binding() {
    let config = OwnerConfig {
        serve: ServeConfig {
            replies: 1,
            ..OWNER.serve
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 64);
        let (at, serial) = upload_at(&mut scene, request(1, 1), &object, TTL_MS);
        let writes = send_all(&mut scene, at, serial, &object, 0..2);
        writes.iter().for_each(|&token| scene.control.hold(token));
        scene.turns(4);
        scene.sent(1);
        let dropped = scene.owner.serve_report().dropped_replies;
        let other = scene.frame(1, Kind::PutCancel, request(2, 1), NAME + 1, cancel(serial));
        let stop = scene.frame(1, Kind::PutCancel, at, NAME, cancel(serial));
        scene.inject(1, &other);
        scene.inject(1, &stop);
        scene.turns(4);
        let sent = scene.sent(1);
        assert!(
            sent.iter().all(|frame| frame.request != at),
            "the full ring dropped the upload's terminal: {sent:?}"
        );
        assert_eq!(scene.owner.serve_report().dropped_replies, dropped + 1);
        assert_eq!(scene.owner.put_report().cancelled, 1);
        assert!(
            slot_bound(&scene, 1),
            "the unsent terminal left the slot bound"
        );
        assert_eq!(scene.owner.census().draining, 1);
        assert_eq!(scene.owner.put_occupancy().live, 1);

        let before = evidence(&scene);
        for (field, header) in changed(&mut scene, at, serial, object.len() as u32) {
            let answer = scene.one(1, &header);
            assert_eq!(
                error(&answer),
                Some(Status::ConflictingRequest),
                "draining: a PREPARE with a changed {field} conflicts: {answer:?}"
            );
            assert!(
                slot_bound(&scene, 1),
                "draining: the conflict on the {field} kept the binding"
            );
            assert_eq!(
                evidence(&scene),
                before,
                "draining: the conflict on the {field} kept the row, custody, census and occupancy"
            );
        }

        let original = scene.frame(
            1,
            Kind::PutPrepare,
            at,
            NAME,
            prepare(serial, object.len() as u32, TTL_MS),
        );
        assert_eq!(
            error(&scene.one(1, &original)),
            Some(Status::Cancelled),
            "the matching duplicate recovers the original terminal"
        );
        assert!(
            !slot_bound(&scene, 1),
            "the replayed terminal freed the binding"
        );
        assert_eq!(
            scene.owner.put_occupancy().live,
            1,
            "the write is still held"
        );
        for &token in &writes {
            scene.control.release(token);
        }
        scene.turns(20);
        assert_eq!(scene.owner.put_occupancy().live, 0);
        assert!(!scene.visible(NAME));
    });
}
