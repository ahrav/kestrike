//! The client's upload outcomes and their finality.
//!
//! `abandon` accepts an upload only when its outcome is `Unknown`: an undecided, `Published`, `Failed` or
//! `NotStarted` upload answers false and keeps its record as it was, so `retire` keeps every undecided upload,
//! while an `Unknown` upload retires only once `abandon` accepted it. Every upload of the `abandon` tests has an
//! empty source chain, so `retire` follows its outcome and `abandon` alone.
//!
//! A `Published`, `Failed` or `NotStarted` outcome is final: once a retained upload has one, the outcome stands
//! through the end of its session, the client's close and every later reply, a matching PUT RESULT or PUT ERROR of
//! its own session and the owner's `UnknownOutcome` included. Only `Unknown` is still settled, by a
//! PUT RESULT or PUT ERROR of the same session. When a frame must preserve an outcome, the post-frame check
//! reports the `receive` result on failure. The session's end and the client's close each decide an undecided
//! upload. A final outcome that survives both calls predates them.

use crate::storage::{CacheVersion, EngineBudget};

use super::adapters::drive;
use super::client_namespace::ClientRequests;
use super::datagram::PeerId;
use super::fetch::Releases;
use super::frame::{Header, Kind, Status};
use super::owner_tests::{PRINCIPALS, key};
use super::put_tests::scene;
use super::requests::{RequestId, RequestTable};
use super::serve::{Manifest, header, manifest_header};
use super::session::{Admitted, Caps};
use super::upload::{UploadConfig, UploadCore, UploadOutcome};

const TTL_MS: u32 = 60_000;

/// An upload with no outcome yet is refused, and the refusal leaves the upload as it was: `retire` still keeps it
/// live, and the upload goes on to publish and retires on that outcome.
#[test]
fn abandon_refuses_an_undecided_upload_and_retire_keeps_it() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 30_000_000)
            .unwrap();
        let client = &mut scene.clients[0];
        assert_eq!(client.put_outcome(id), None);
        assert!(!client.abandon(id), "no outcome is not `Unknown`");
        assert!(!client.retire(id), "an undecided upload stays live");
        assert_eq!(client.put_outcome(id), None);

        drive(&mut scene, 4);
        let client = &mut scene.clients[0];
        assert!(!client.abandon(id), "undecided after the owner's authority");
        assert!(!client.retire(id), "an undecided upload stays live");
        client.prepare(id, 0, 0, TTL_MS).unwrap();
        drive(&mut scene, 10);
        let client = &mut scene.clients[0];
        assert_eq!(client.put_outcome(id), Some(UploadOutcome::Published));
        assert!(!client.abandon(id), "`Published` is not `Unknown`");
        assert_eq!(client.put_outcome(id), Some(UploadOutcome::Published));
        assert!(
            client.retire(id),
            "a published upload retires on its outcome"
        );
        assert!(!client.abandon(id), "a retired upload has no record");
    });
}

/// The one accepted outcome: an `Unknown` upload stays live through `retire` until `abandon` accepts it.
#[test]
fn abandon_accepts_an_unknown_upload_which_then_retires() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 50_000)
            .unwrap();
        let client = &mut scene.clients[0];
        for turn in 0..1_000 {
            client.poll(now + turn * 100);
        }
        assert_eq!(client.put_outcome(id), Some(UploadOutcome::Unknown));
        assert!(!client.retire(id), "`Unknown` waits for the abandon");
        assert!(client.abandon(id));
        assert_eq!(client.put_outcome(id), Some(UploadOutcome::Unknown));
        assert!(client.retire(id));
        assert_eq!(client.put_outcome(id), None);
    });
}

/// The owner's PUT grant names only the other client's principal, so this client's upload ends
/// `Failed(PermissionDenied)`. `abandon` refuses that outcome and leaves it, and the upload retires on it.
#[test]
fn abandon_refuses_a_failed_upload() {
    scene(&PRINCIPALS[1..], |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 30_000_000)
            .unwrap();
        drive(&mut scene, 6);
        let client = &mut scene.clients[0];
        let failed = Some(UploadOutcome::Failed(Status::PermissionDenied));
        assert_eq!(client.put_outcome(id), failed);
        assert!(!client.abandon(id), "`Failed` is not `Unknown`");
        assert_eq!(client.put_outcome(id), failed);
        assert!(client.retire(id), "a failed upload retires on its outcome");
    });
}

/// The upload's deadline passes before any send call took its BEGIN, so the upload ends `NotStarted`. `abandon`
/// refuses that outcome and leaves it, and the upload retires on it.
#[test]
fn abandon_refuses_an_upload_that_has_not_started() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 1_000)
            .unwrap();
        let client = &mut scene.clients[0];
        client.poll(now + 1_000);
        assert_eq!(client.put_outcome(id), Some(UploadOutcome::NotStarted));
        assert!(!client.abandon(id), "`NotStarted` is not `Unknown`");
        assert_eq!(client.put_outcome(id), Some(UploadOutcome::NotStarted));
        assert!(
            client.retire(id),
            "an unstarted upload retires on its outcome"
        );
    });
}

const SESSION: Admitted = Admitted {
    peer: PeerId(0),
    epoch: 1,
    caps: Caps {
        slots: 4,
        window: 4,
    },
};
/// The same peer under its next session.
const FOREIGN: Admitted = Admitted {
    epoch: 2,
    ..SESSION
};
const DEADLINE_US: u64 = 1_000_000;
const SERIAL: u64 = 5;

/// How a test's upload reaches the outcome it starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reached {
    /// PUT RESULT answered the prepared upload.
    Published,
    /// PUT ERROR answered the prepared upload with a refusal.
    Failed,
    /// The deadline passed before any send call took its BEGIN.
    NotStarted,
    /// PUT ERROR answered that the owner could not tell.
    Unknown,
}

impl Reached {
    fn outcome(self) -> UploadOutcome {
        match self {
            Self::Published => UploadOutcome::Published,
            Self::Failed => UploadOutcome::Failed(Status::RequestPressure),
            Self::NotStarted => UploadOutcome::NotStarted,
            Self::Unknown => UploadOutcome::Unknown,
        }
    }
}

fn sent(core: &mut UploadCore<'_>, requests: &mut ClientRequests<'_>, now_us: u64) -> Vec<Kind> {
    let mut kinds = Vec::new();
    core.poll(requests, now_us, 8, |_, header| {
        kinds.push(header.kind);
        true
    });
    kinds
}

/// The owner's reply of `kind` to upload `id`, with the manifest a RESULT
/// carries once the shape is prepared; only a PUT ERROR carries `status`.
fn reply(id: RequestId, requests: &ClientRequests<'_>, kind: Kind, status: Status) -> Header {
    let upload = requests.upload(id).unwrap();
    let (wire, key) = (upload.wire(), upload.key());
    let mut reply = match (kind, upload.prepared()) {
        (Kind::PutResult, Some((metadata_len, body_len))) => {
            let manifest = Manifest {
                allocation: SERIAL,
                metadata_len,
                body_len,
            };
            manifest_header(kind, wire, key, &manifest)
        }
        _ => Header {
            allocation: SERIAL,
            ..header(kind, wire, key)
        },
    };
    if kind == Kind::PutError {
        reply.status = status as u16;
    }
    reply
}

/// Runs `check` on one upload of session [`SESSION`] that is admitted and
/// undecided, and whose BEGIN no send call took.
fn with_admitted(check: impl FnOnce(&mut UploadCore<'_>, &mut ClientRequests<'_>, RequestId)) {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            DEADLINE_US,
        )
        .unwrap();
    check(&mut core, &mut requests, id);
}

/// Sends the upload's BEGIN and delivers the owner's AUTHORITY, which leaves
/// the upload undecided with a frame at the owner.
fn begin(core: &mut UploadCore<'_>, requests: &mut ClientRequests<'_>, id: RequestId) {
    assert_eq!(sent(core, requests, 0), [Kind::PutBegin]);
    let authority = reply(id, requests, Kind::PutAuthority, Status::Missing);
    assert!(core.receive(requests, SESSION, &authority, 10));
}

/// Runs `check` on one retained upload of session [`SESSION`] that reached
/// its outcome as `reached` says.
fn with_upload(
    reached: Reached,
    check: impl FnOnce(&mut UploadCore<'_>, &mut ClientRequests<'_>, RequestId),
) {
    with_admitted(|core, requests, id| {
        if reached == Reached::NotStarted {
            core.tick(requests, 2 * DEADLINE_US);
        } else {
            begin(core, requests, id);
            core.prepare(requests, id, 0, 0, 60_000).unwrap();
            assert_eq!(sent(core, requests, 20), [Kind::PutPrepare]);
            let decision = match reached {
                Reached::Published => reply(id, requests, Kind::PutResult, Status::Missing),
                Reached::Failed => reply(id, requests, Kind::PutError, Status::RequestPressure),
                _ => reply(id, requests, Kind::PutError, Status::UnknownOutcome),
            };
            assert!(core.receive(requests, SESSION, &decision, 30));
        }
        assert_eq!(
            core.outcome(requests, id),
            Some(reached.outcome()),
            "{reached:?}"
        );
        check(core, requests, id);
    });
}

/// How an upload reaches each of the three final outcomes: `Published`, `Failed` and `NotStarted`.
const KNOWN: [Reached; 3] = [Reached::Published, Reached::Failed, Reached::NotStarted];

/// The terminal frames an owner may still send for a request: its RESULT, a
/// refusal, and the answer that it could not tell.
const LATE: [(Kind, Status); 3] = [
    (Kind::PutResult, Status::Missing),
    (Kind::PutError, Status::TooLarge),
    (Kind::PutError, Status::UnknownOutcome),
];

/// `end_session` and `close_all` decide an undecided upload `Unknown` or `NotStarted`, and a `Published`, `Failed` or
/// `NotStarted` outcome is final: a retained upload with one of them keeps it through the end of its session
/// followed by the client's close, through the close followed by the end of its session, and through each call a
/// second time.
#[test]
fn the_end_of_its_session_and_the_client_s_close_leave_each_known_outcome() {
    for reached in KNOWN {
        for close_first in [false, true] {
            with_upload(reached, |core, requests, id| {
                keeps_through_the_ends(core, requests, id, Some(reached.outcome()), close_first);
            });
        }
    }
}

/// Alternates the client's close and the end of upload `id`'s session, twice each, starting with the close when
/// `close_first` is set and with the session's end otherwise, and checks after each call that the upload's outcome
/// is still `outcome`.
fn keeps_through_the_ends(
    core: &mut UploadCore<'_>,
    requests: &mut ClientRequests<'_>,
    id: RequestId,
    outcome: Option<UploadOutcome>,
    close_first: bool,
) {
    for call in 0..4 {
        let closes = (call % 2 == 0) == close_first;
        if closes {
            core.close_all(requests);
        } else {
            core.end_session(requests, SESSION.epoch);
        }
        assert_eq!(
            core.outcome(requests, id),
            outcome,
            "a known outcome stands: {outcome:?} after call {call} from {}",
            if close_first {
                "the client's close"
            } else {
                "the session's end"
            }
        );
    }
}

/// The control for finality: the same calls over an upload that the owner's AUTHORITY answered and nothing decided
/// change its outcome, since the end of its session decides it, as the end of a session overwrites a decided
/// outcome when the decision has no guard.
#[test]
#[should_panic(expected = "a known outcome stands: None after call 0 from the session's end")]
fn negative_control_the_end_of_its_session_decides_an_undecided_upload() {
    with_admitted(|core, requests, id| {
        begin(core, requests, id);
        keeps_through_the_ends(core, requests, id, None, false);
    });
}

/// The end of its session and the client's close each decide an undecided upload: `Unknown` once the owner's
/// AUTHORITY answered it, `NotStarted` while its BEGIN is unsent. The end of the peer's next session, run first,
/// leaves both undecided.
#[test]
fn the_end_of_its_session_and_the_client_s_close_decide_an_undecided_upload() {
    for (answered, decided) in [
        (true, UploadOutcome::Unknown),
        (false, UploadOutcome::NotStarted),
    ] {
        for closes in [false, true] {
            with_admitted(|core, requests, id| {
                if answered {
                    begin(core, requests, id);
                }
                core.end_session(requests, FOREIGN.epoch);
                assert_eq!(
                    core.outcome(requests, id),
                    None,
                    "the end of another session decides no upload (answered: {answered})"
                );
                if closes {
                    core.close_all(requests);
                } else {
                    core.end_session(requests, SESSION.epoch);
                }
                assert_eq!(
                    core.outcome(requests, id),
                    Some(decided),
                    "an undecided upload (answered: {answered}) after {}",
                    if closes {
                        "the client closed"
                    } else {
                        "its session ended"
                    }
                );
            });
        }
    }
}

/// A PUT RESULT, a PUT ERROR with a refusal and a PUT ERROR `UnknownOutcome` that name a retained `Published`,
/// `Failed` or `NotStarted` upload in its own session each leave the outcome as it was, and so do the session's end
/// and the client's close after the frame.
#[test]
fn a_matching_reply_of_the_same_session_leaves_each_known_outcome() {
    for reached in KNOWN {
        for (kind, status) in LATE {
            with_upload(reached, |core, requests, id| {
                let late = reply(id, requests, kind, status);
                let taken = core.receive(requests, SESSION, &late, 40);
                assert_eq!(
                    core.outcome(requests, id),
                    Some(reached.outcome()),
                    "{reached:?} after a {kind:?} {status:?} that `receive` answered {taken}"
                );
                core.end_session(requests, SESSION.epoch);
                core.close_all(requests);
                assert_eq!(
                    core.outcome(requests, id),
                    Some(reached.outcome()),
                    "{reached:?} after a {kind:?} {status:?}, its session's end and the client's close"
                );
            });
        }
    }
}

/// A PUT RESULT or PUT ERROR admitted under the same peer's next session settles no upload: the outcome, `Unknown`
/// included, stands after each of the three late terminal frames, and the end of that next session leaves it as
/// well.
#[test]
fn a_reply_of_another_session_settles_no_upload() {
    for reached in [
        Reached::Published,
        Reached::Failed,
        Reached::NotStarted,
        Reached::Unknown,
    ] {
        for (kind, status) in LATE {
            with_upload(reached, |core, requests, id| {
                let foreign = reply(id, requests, kind, status);
                let taken = core.receive(requests, FOREIGN, &foreign, 40);
                assert_eq!(
                    core.outcome(requests, id),
                    Some(reached.outcome()),
                    "{reached:?} after a {kind:?} {status:?} of another session that `receive` answered {taken}"
                );
                core.end_session(requests, FOREIGN.epoch);
                assert_eq!(core.outcome(requests, id), Some(reached.outcome()));
            });
        }
    }
}

/// An upload that ended `Unknown` stays `Unknown` through the end of its session and the client's close, and a PUT
/// RESULT of that session then settles it `Published`, which a further session end and close leave. A PUT ERROR
/// with a refusal settles another `Unknown` upload `Failed` with the error's status, which the client's close leaves.
#[test]
fn an_unknown_upload_is_still_settled_by_a_result_or_error_of_its_session() {
    with_upload(Reached::Unknown, |core, requests, id| {
        core.end_session(requests, SESSION.epoch);
        core.close_all(requests);
        assert_eq!(core.outcome(requests, id), Some(UploadOutcome::Unknown));
        let result = reply(id, requests, Kind::PutResult, Status::Missing);
        assert!(core.receive(requests, SESSION, &result, 40));
        assert_eq!(core.outcome(requests, id), Some(UploadOutcome::Published));
        core.end_session(requests, SESSION.epoch);
        core.close_all(requests);
        assert_eq!(
            core.outcome(requests, id),
            Some(UploadOutcome::Published),
            "the settled outcome is final"
        );
    });
    with_upload(Reached::Unknown, |core, requests, id| {
        let error = reply(id, requests, Kind::PutError, Status::TooLarge);
        assert!(core.receive(requests, SESSION, &error, 40));
        assert_eq!(
            core.outcome(requests, id),
            Some(UploadOutcome::Failed(Status::TooLarge))
        );
        core.close_all(requests);
        assert_eq!(
            core.outcome(requests, id),
            Some(UploadOutcome::Failed(Status::TooLarge))
        );
    });
}

/// One `Published`, one `Failed` and one `NotStarted` upload each receive all three late terminal frames one after
/// another, and the outcome stands after each: a late frame leaves the upload as final for the next frame as it was
/// for the first.
#[test]
fn one_upload_with_a_final_outcome_keeps_it_after_every_late_terminal_in_sequence() {
    for reached in KNOWN {
        with_upload(reached, |core, requests, id| {
            for (at, (kind, status)) in LATE.into_iter().enumerate() {
                let late = reply(id, requests, kind, status);
                let taken = core.receive(requests, SESSION, &late, 40 + at as u64);
                assert_eq!(
                    core.outcome(requests, id),
                    Some(reached.outcome()),
                    "{reached:?} after a {kind:?} {status:?} that `receive` answered {taken}"
                );
            }
        });
    }
}

/// The frames that leave a final outcome still settle an upload that ended `Unknown`. A PUT ERROR `UnknownOutcome`
/// leaves it `Unknown`, and a PUT RESULT then publishes it. A PUT ERROR with a refusal fails another,
/// and a late `UnknownOutcome` then leaves the `Failed` outcome.
#[test]
fn an_upload_that_ended_unknown_is_settled_by_the_same_frames() {
    with_upload(Reached::Unknown, |core, requests, id| {
        let again = reply(id, requests, Kind::PutError, Status::UnknownOutcome);
        let taken = core.receive(requests, SESSION, &again, 40);
        assert_eq!(
            core.outcome(requests, id),
            Some(UploadOutcome::Unknown),
            "`Unknown` after a second `UnknownOutcome` that `receive` answered {taken}"
        );
        settles_the_unknown_upload(core, requests, id, SESSION);
    });
    with_upload(Reached::Unknown, |core, requests, id| {
        let error = reply(id, requests, Kind::PutError, Status::TooLarge);
        assert!(core.receive(requests, SESSION, &error, 40));
        assert_eq!(
            core.outcome(requests, id),
            Some(UploadOutcome::Failed(Status::TooLarge))
        );
        let late = reply(id, requests, Kind::PutError, Status::UnknownOutcome);
        let taken = core.receive(requests, SESSION, &late, 50);
        assert_eq!(
            core.outcome(requests, id),
            Some(UploadOutcome::Failed(Status::TooLarge)),
            "the settled outcome is final after an `UnknownOutcome` that `receive` answered {taken}"
        );
    });
}

/// Offers upload `id`, which ended `Unknown`, a PUT RESULT admitted under `session`, which must take it and
/// publish the upload.
fn settles_the_unknown_upload(
    core: &mut UploadCore<'_>,
    requests: &mut ClientRequests<'_>,
    id: RequestId,
    session: Admitted,
) {
    let result = reply(id, requests, Kind::PutResult, Status::Missing);
    assert!(
        core.receive(requests, session, &result, 50),
        "`receive` takes its session's PUT RESULT for an `Unknown` upload"
    );
    assert_eq!(core.outcome(requests, id), Some(UploadOutcome::Published));
}

/// The control for the settling frame: the PUT RESULT arrives under the peer's next session, which the upload does
/// not belong to, so `receive` refuses it, as a core that admits no frame to an `Unknown` upload refuses it.
#[test]
#[should_panic(expected = "`receive` takes its session's PUT RESULT for an `Unknown` upload")]
fn negative_control_a_result_of_another_session_leaves_the_unknown_upload() {
    with_upload(Reached::Unknown, |core, requests, id| {
        settles_the_unknown_upload(core, requests, id, FOREIGN);
    });
}

/// Each pair records the call result and subsequent outcome for `id`, in `close`, `abandon`, `close` order. A
/// skipped first `close` contributes `(false, initial outcome)`.
fn closed_and_abandoned(
    core: &mut UploadCore<'_>,
    requests: &mut ClientRequests<'_>,
    id: RequestId,
    close_first: bool,
) -> [(bool, Option<UploadOutcome>); 3] {
    let first = close_first && core.close(requests, id);
    let first = (first, core.outcome(requests, id));
    let abandon = (core.abandon(requests, id), core.outcome(requests, id));
    let second = (core.close(requests, id), core.outcome(requests, id));
    [first, abandon, second]
}

#[test]
fn abandon_refuses_an_upload_with_no_outcome_and_close_keeps_it() {
    for (stage, name) in ["queued", "authorized", "prepared"].into_iter().enumerate() {
        for close_first in [false, true] {
            with_admitted(|core, requests, id| {
                if stage > 0 {
                    begin(core, requests, id);
                }
                if stage > 1 {
                    core.prepare(requests, id, 0, 0, 60_000).unwrap();
                    assert_eq!(sent(core, requests, 20), [Kind::PutPrepare]);
                }
                assert_eq!(core.outcome(requests, id), None);
                assert_eq!(
                    closed_and_abandoned(core, requests, id, close_first),
                    [(false, None), (false, None), (false, None)],
                    "a {name} upload, close first {close_first}"
                );
                assert!(requests.upload(id).is_some(), "a {name} upload");
            });
        }
    }
}

#[test]
fn abandon_refuses_a_published_failed_or_unstarted_upload_and_leaves_its_outcome() {
    for reached in KNOWN {
        with_upload(reached, |core, requests, id| {
            let outcome = Some(reached.outcome());
            assert_eq!(
                closed_and_abandoned(core, requests, id, false),
                [(false, outcome), (false, outcome), (true, None)],
                "{reached:?}"
            );
        });
    }
}

#[test]
fn close_releases_a_published_failed_or_unstarted_upload_on_its_outcome() {
    for reached in KNOWN {
        with_upload(reached, |core, requests, id| {
            assert_eq!(
                closed_and_abandoned(core, requests, id, true),
                [(true, None), (false, None), (false, None)],
                "{reached:?}"
            );
        });
    }
}

#[test]
fn close_keeps_an_unknown_upload_until_abandon_accepted_it() {
    for close_first in [false, true] {
        with_upload(Reached::Unknown, |core, requests, id| {
            let unknown = Some(UploadOutcome::Unknown);
            assert_eq!(
                closed_and_abandoned(core, requests, id, close_first),
                [(false, unknown), (true, unknown), (true, None)],
                "close first {close_first}"
            );
        });
    }
}
