//! Parked GETs end to end: a GET whose lookup proves the key missing joins
//! the upload in progress, waits under its own deadline, caps and cause, and
//! reads the producer's version or ends with the producer's terminal, while
//! the producer's deadline and lifetime stay its own.

use crate::sim::round::Actor;
use crate::storage::FillFailure;

use super::adapters::{FRAGMENT, upload};
use super::datagram::PeerId;
use super::fetch::Outcome;
use super::frame::{Kind, Status};
use super::link::Faults;
use super::owner::OwnerConfig;
use super::owner_tests::{OWNER, PRINCIPALS, key, payload};
use super::parked::{End, FollowConfig, PLANT, Plant, failure_status};
use super::put::fill_failure;
use super::put_tests::{Scene, request, scene, scene_with};
use super::requests::RequestId;
use super::upload::UploadOutcome;

/// The key every test uploads.
const NAME: u8 = 6;

fn fragment(object: &[u8], index: u32) -> &[u8] {
    let start = index as usize * FRAGMENT;
    &object[start..object.len().min(start + FRAGMENT)]
}

/// `turns` turns that poll both clients before the owner.
fn drive(scene: &mut Scene<'_, '_>, turns: u64) {
    for _ in 0..turns {
        scene.turn_with(&mut [
            (Actor::Client(0), &mut |clients, _, now| {
                let _ = clients[0].poll(now);
            }),
            (Actor::Client(1), &mut |clients, _, now| {
                let _ = clients[1].poll(now);
            }),
        ]);
    }
}

/// Client 0's upload of a two-fragment object under key [`NAME`], prepared
/// with its first fragment supplied, so the fill stays open until the
/// second fragment arrives.
fn open_upload(scene: &mut Scene<'_, '_>) -> (RequestId, Vec<u8>) {
    let object = payload(2 * FRAGMENT, 61);
    let id = upload(scene, NAME, &object, 30_000_000);
    scene.clients[0]
        .supply(id, 0, fragment(&object, 0))
        .unwrap();
    drive(scene, 10);
    assert_eq!(scene.clients[0].put_outcome(id), None, "the upload is open");
    (id, object)
}

/// Supplies the open upload's second fragment.
fn finish_upload(scene: &mut Scene<'_, '_>, id: RequestId, object: &[u8]) {
    scene.clients[0].supply(id, 1, fragment(object, 1)).unwrap();
}

/// Client `reader`'s GET of [`NAME`] waiting at most `wait_us`.
fn get(scene: &mut Scene<'_, '_>, reader: usize, wait_us: u64) -> RequestId {
    let now = scene.turn * 100;
    scene.clients[reader]
        .get(key(NAME), 0, 1 << 20, now, wait_us)
        .unwrap()
}

/// Drives until client `reader`'s GET `id` decides, collecting its bytes.
fn collect(scene: &mut Scene<'_, '_>, reader: usize, id: RequestId) -> (Option<Outcome>, Vec<u8>) {
    let mut bytes = Vec::new();
    for _ in 0..2_000 {
        drive(scene, 1);
        while let Some(fragment) = scene.clients[reader].take(id) {
            bytes.extend_from_slice(fragment.bytes());
        }
        if scene.clients[reader].outcome(id).is_some() {
            break;
        }
    }
    (scene.clients[reader].outcome(id), bytes)
}

/// Drives until the upload decides, returning its outcome.
fn uploaded(scene: &mut Scene<'_, '_>, id: RequestId) -> Option<UploadOutcome> {
    for _ in 0..2_000 {
        if scene.clients[0].put_outcome(id).is_some() {
            break;
        }
        drive(scene, 1);
    }
    scene.clients[0].put_outcome(id)
}

/// The parked GETs' count, each peer's count and each entry's fill observer
/// count, checked against each other.
fn parked(scene: &Scene<'_, '_>) -> u32 {
    if let Err(census) = scene.owner.check_parked_census() {
        panic!("the parked GETs left the request census: {census}");
    }
    let view = scene.owner.parked_view();
    assert_eq!(view.entries.len(), view.count as usize, "{view:?}");
    assert_eq!(view.by_peer.iter().sum::<u32>(), view.count, "{view:?}");
    for (_, peer, observers) in &view.entries {
        let of_peer = view.entries.iter().filter(|entry| entry.1 == *peer).count();
        assert_eq!(view.by_peer[usize::from(peer.0)] as usize, of_peer);
        assert!(*observers >= 1, "a parked follower is counted on its fill");
    }
    view.count
}

/// A GET of a key under upload joins the upload's fill and parks, then reads
/// the version the upload published, exactly; the parked state drains.
#[test]
fn a_missing_get_parks_behind_an_upload_and_reads_its_version() {
    scene(&PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let id = get(&mut scene, 1, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 1, "the GET parked");
        assert_eq!(scene.clients[1].outcome(id), None);
        finish_upload(&mut scene, put, &object);
        let (outcome, bytes) = collect(&mut scene, 1, id);
        assert_eq!(outcome, Some(Outcome::Complete));
        assert_eq!(bytes, object, "the follower read the published version");
        assert_eq!(uploaded(&mut scene, put), Some(UploadOutcome::Published));
        assert_eq!(parked(&scene), 0);
        let report = scene.owner.report().parked;
        assert_eq!((report.joined, report.woke, report.high_water), (1, 1, 1));
    });
}

#[test]
fn a_get_parked_past_retry_us_wakes_without_a_retry() {
    scene(&PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let id = get(&mut scene, 1, 30_000_000);
        let parked_turns = 2 * OWNER.serve.retry_us / 100;
        drive(&mut scene, parked_turns);
        assert_eq!(parked(&scene), 1, "the GET parked past retry_us");
        finish_upload(&mut scene, put, &object);
        // The reader's ACKs arrive after the owner has ticked over the woken read.
        for _ in 0..OWNER.serve.retry_us / 400 {
            scene.turn_with(&mut [(Actor::Client(0), &mut |clients, _, now| {
                let _ = clients[0].poll(now);
            })]);
        }
        assert_eq!(parked(&scene), 0, "the GET woke");
        assert_eq!(
            scene.owner.serve_report().retries,
            0,
            "the wake is no loss retry"
        );
        let (outcome, bytes) = collect(&mut scene, 1, id);
        assert_eq!(outcome, Some(Outcome::Complete));
        assert_eq!(bytes, object);
        assert_eq!(scene.owner.serve_report().retries, 0);
    });
}

#[test]
fn the_largest_wake_allowance_parks_and_wakes_a_get() {
    let config = OwnerConfig {
        follow: FollowConfig {
            wake: u32::MAX,
            ..OWNER.follow
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let id = get(&mut scene, 1, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 1, "the GET parked");
        finish_upload(&mut scene, put, &object);
        let (outcome, bytes) = collect(&mut scene, 1, id);
        assert_eq!(outcome, Some(Outcome::Complete));
        assert_eq!(bytes, object, "the follower read the published version");
        assert_eq!(parked(&scene), 0);
    });
}

/// The first follower's own deadline ends it `TimedOut` while the producer
/// uploads on, and the second follower then reads the published version.
fn first_times_out_second_reads() {
    scene(&PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let first = get(&mut scene, 1, 3_000);
        let second = get(&mut scene, 1, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 2, "both GETs parked");
        let (outcome, _) = collect(&mut scene, 1, first);
        assert!(
            matches!(outcome, Some(Outcome::Failed(Status::TimedOut))),
            "{outcome:?}"
        );
        drive(&mut scene, 20);
        assert_eq!(parked(&scene), 1, "the first follower detached");
        assert_eq!(scene.owner.report().parked.detached, 1);
        finish_upload(&mut scene, put, &object);
        let (outcome, bytes) = collect(&mut scene, 1, second);
        let published = uploaded(&mut scene, put);
        assert!(
            outcome == Some(Outcome::Complete)
                && bytes == object
                && published == Some(UploadOutcome::Published),
            "the producer outlives its first follower: {outcome:?}, {published:?}"
        );
        assert_eq!(parked(&scene), 0);
    });
}

#[test]
fn the_first_follower_times_out_and_the_second_reads() {
    first_times_out_second_reads();
}

/// The planted owner aborts the producer when the first follower detaches,
/// which the producer-independence check rejects.
#[test]
#[should_panic(expected = "the producer outlives its first follower")]
fn negative_control_a_first_detach_that_aborts_the_producer_fails() {
    PLANT.with(|plant| plant.set(Plant::DetachAborts));
    first_times_out_second_reads();
}

/// A duplicate GET naming a longer wait leaves the parked request's deadline
/// where it was: the request ends `TimedOut` at its first deadline.
fn a_duplicate_tightens_only() {
    scene(&PRINCIPALS, |mut scene| {
        let (_put, _object) = open_upload(&mut scene);
        let at = request(2, 1);
        let mut short = scene.get(1, at, NAME);
        short.remaining_ms = 3;
        scene.inject(1, &short);
        drive(&mut scene, 5);
        assert_eq!(parked(&scene), 1);
        let deadline = scene.owner.parked_view().deadlines;
        let mut long = scene.get(1, at, NAME);
        long.remaining_ms = 60_000;
        scene.inject(1, &long);
        drive(&mut scene, 1);
        if !super::parked::planted(Plant::DuplicateExtends) {
            assert_eq!(
                scene.owner.parked_view().deadlines,
                deadline,
                "the deadline held"
            );
        }
        let mut ended = None;
        for turn in 0..60 {
            drive(&mut scene, 1);
            if scene
                .sent(1)
                .iter()
                .any(|frame| frame.kind == Kind::Error && frame.request == at)
            {
                ended = Some(turn);
                break;
            }
        }
        assert!(
            ended.is_some(),
            "the duplicate left the first deadline in place"
        );
        drive(&mut scene, 5);
        assert_eq!(parked(&scene), 0);
    });
}

#[test]
fn a_duplicate_only_tightens_the_parked_deadline() {
    a_duplicate_tightens_only();
}

/// A duplicate naming a shorter wait moves the parked request's deadline
/// earlier: the request ends `TimedOut` at the duplicate's deadline.
#[test]
fn a_shorter_duplicate_tightens_the_parked_deadline() {
    scene(&PRINCIPALS, |mut scene| {
        let (_put, _object) = open_upload(&mut scene);
        let at = request(2, 1);
        let mut long = scene.get(1, at, NAME);
        long.remaining_ms = 60_000;
        scene.inject(1, &long);
        drive(&mut scene, 5);
        assert_eq!(parked(&scene), 1);
        let mut short = scene.get(1, at, NAME);
        short.remaining_ms = 3;
        scene.inject(1, &short);
        let ended = (0..60).any(|_| {
            drive(&mut scene, 1);
            scene
                .sent(1)
                .iter()
                .any(|frame| frame.kind == Kind::Error && frame.request == at)
        });
        assert!(ended, "the duplicate's shorter wait ended the request");
        drive(&mut scene, 5);
        assert_eq!(parked(&scene), 0);
        assert_eq!(scene.owner.report().parked.detached, 1);
    });
}

/// A parked slot released before its follower detached leaves the parked
/// table naming a request the namespace no longer holds, which the census
/// check rejects.
#[test]
#[should_panic(expected = "the parked GETs left the request census")]
fn negative_control_a_parked_slot_released_before_its_detach_fails_the_census() {
    PLANT.with(|plant| plant.set(Plant::ReleaseParked));
    let config = OwnerConfig {
        follow: FollowConfig {
            wake: 1,
            ..OWNER.follow
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let (_put, _object) = open_upload(&mut scene);
        let first = get(&mut scene, 1, 30_000_000);
        let _second = get(&mut scene, 1, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 2);
        scene.clients[1].cancel(first);
        for _ in 0..20 {
            drive(&mut scene, 1);
            parked(&scene);
        }
    });
}

/// The planted duplicate extends the wait, which the tightening check
/// rejects.
#[test]
#[should_panic(expected = "the duplicate left the first deadline in place")]
fn negative_control_a_duplicate_that_extends_the_wait_fails() {
    PLANT.with(|plant| plant.set(Plant::DuplicateExtends));
    a_duplicate_tightens_only();
}

/// Each follower cap, once full, refuses a further joining GET
/// `RequestPressure` and counts the cap, and the parked GETs within it read.
#[test]
fn each_follower_cap_refuses_request_pressure_at_saturation() {
    let caps = [
        FollowConfig {
            followers: 1,
            ..OWNER.follow
        },
        FollowConfig {
            peer_followers: 1,
            ..OWNER.follow
        },
        FollowConfig {
            fill_followers: 1,
            ..OWNER.follow
        },
    ];
    for (at, follow) in caps.into_iter().enumerate() {
        let config = OwnerConfig { follow, ..OWNER };
        scene_with(config, &PRINCIPALS, |mut scene| {
            let (put, object) = open_upload(&mut scene);
            let first = get(&mut scene, 1, 30_000_000);
            drive(&mut scene, 10);
            assert_eq!(parked(&scene), 1);
            let refused = get(&mut scene, 1, 30_000_000);
            let (outcome, _) = collect(&mut scene, 1, refused);
            assert_eq!(
                outcome,
                Some(Outcome::Pressure(Status::RequestPressure)),
                "cap {at}"
            );
            if at > 0 {
                // The peer and fill caps count their own peer and fill: the
                // uploading peer's GET of the same key parks under the peer
                // cap, and is refused under the fill cap.
                let other = get(&mut scene, 0, 30_000_000);
                drive(&mut scene, 10);
                let outcome = scene.clients[0].outcome(other);
                if at == 1 {
                    assert_eq!(outcome, None, "another peer's GET parks");
                    assert_eq!(parked(&scene), 2);
                } else {
                    let (outcome, _) = collect(&mut scene, 0, other);
                    assert_eq!(outcome, Some(Outcome::Pressure(Status::RequestPressure)));
                }
            }
            let report = scene.owner.report().parked;
            let counted = [
                report.total_saturated,
                report.peer_saturated,
                report.fill_saturated,
            ];
            let mut expected = [0; 3];
            expected[at] = if at == 2 { 2 } else { 1 };
            assert_eq!(counted, expected, "cap {at}");
            finish_upload(&mut scene, put, &object);
            let (outcome, bytes) = collect(&mut scene, 1, first);
            assert_eq!(outcome, Some(Outcome::Complete), "cap {at}");
            assert_eq!(bytes, object);
        });
    }
}

/// A producer's ordinary end reaches its followers as `Missing`: a cancelled
/// upload and an invalidated one.
#[test]
fn ordinary_producer_ends_reach_followers_as_missing() {
    for invalidate in [false, true] {
        scene(&PRINCIPALS, |mut scene| {
            let (put, object) = open_upload(&mut scene);
            let id = get(&mut scene, 1, 30_000_000);
            drive(&mut scene, 10);
            assert_eq!(parked(&scene), 1);
            if invalidate {
                let mut budget = crate::storage::WorkBudget::new(1 << 12);
                scene.owner.invalidate(&key(NAME), 4, &mut budget).unwrap();
                // The revoked producer departs once its publication sees the revocation.
                finish_upload(&mut scene, put, &object);
            } else {
                scene.clients[0].cancel(put);
            }
            let (outcome, _) = collect(&mut scene, 1, id);
            assert_eq!(outcome, Some(Outcome::Missing), "invalidate {invalidate}");
            assert_eq!(parked(&scene), 0);
            let ends = scene.owner.parked_view().ends;
            assert!(
                matches!(ends.as_slice(), [(_, End::Ended(Status::Missing))]),
                "{ends:?}"
            );
            assert_eq!(scene.owner.report().parked.ended, 1);
        });
    }
}

/// A producer's typed failure reaches its followers with the status it
/// recorded: an upload whose own deadline passes ends `TimedOut`, and its
/// follower, whose deadline is later, ends `TimedOut` as the producer's
/// cause.
#[test]
fn a_typed_producer_failure_reaches_its_follower_with_its_status() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT, 62);
        let put = upload(&mut scene, NAME, &object, 40_000);
        scene.clients[0]
            .supply(put, 0, fragment(&object, 0))
            .unwrap();
        let id = get(&mut scene, 1, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 1);
        let (outcome, _) = collect(&mut scene, 1, id);
        assert_eq!(outcome, Some(Outcome::Failed(Status::TimedOut)));
        assert!(matches!(
            uploaded(&mut scene, put),
            Some(UploadOutcome::Failed(_))
        ));
        assert_eq!(scene.owner.report().parked.ended, 1);
        assert_eq!(scene.owner.report().parked.detached, 0);
    });
}

/// A wake visit parks again on an acquisition that met a busy gate, ran out
/// of its visit's work or found the producer pending, so the request's own
/// deadline bounds its retries; every other refusal ends the GET with the
/// status of its cause, and only `LeaseLimit` and `Corrupt` count as owner
/// defects.
#[test]
fn transient_acquisition_refusals_keep_the_get_parked() {
    use crate::storage::JoinedReadError;
    for error in [
        JoinedReadError::Pending,
        JoinedReadError::Contended,
        JoinedReadError::BudgetExhausted,
    ] {
        assert_eq!(super::parked::joined_status(error), None, "{error:?}");
    }
    let ended = [
        (JoinedReadError::Missing, Status::Missing, false),
        (JoinedReadError::Expired, Status::Expired, false),
        (
            JoinedReadError::ClockUnavailable,
            Status::ClockUnavailable,
            false,
        ),
        (JoinedReadError::Closed, Status::Closed, false),
        (JoinedReadError::LeaseLimit, Status::LeasePressure, true),
        (JoinedReadError::RetainLimit, Status::ObjectPressure, false),
        (JoinedReadError::Corrupt, Status::OwnerUnavailable, true),
        (
            JoinedReadError::Failed(FillFailure::DeviceError),
            Status::DeviceError,
            false,
        ),
    ];
    for (error, status, defect) in ended {
        assert_eq!(
            super::parked::joined_status(error),
            Some((status, defect)),
            "{error:?}"
        );
    }
}

/// Every recorded producer failure maps back to the upload status that
/// recorded it, so a follower reports the producer's own cause.
#[test]
fn producer_failures_map_to_the_statuses_that_recorded_them() {
    for failure in FillFailure::ALL {
        let status = failure_status(failure);
        assert!(status.is_get(), "{failure:?}");
        assert_eq!(fill_failure(status), Some(failure));
    }
}

/// A follower whose ERROR the link blocks keeps its terminal: once the link
/// clears, the client receives the producer's `Missing`.
#[test]
fn a_blocked_reply_keeps_the_followers_terminal() {
    scene(&PRINCIPALS, |mut scene| {
        let (put, _object) = open_upload(&mut scene);
        let id = get(&mut scene, 1, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 1);
        let block = Faults {
            would_block: 100,
            ..Faults::default()
        };
        scene.nets[1].borrow_mut().set_faults(0, block);
        scene.clients[0].cancel(put);
        drive(&mut scene, 40);
        assert_eq!(
            parked(&scene),
            0,
            "the producer's terminal ended the follower"
        );
        assert_eq!(scene.owner.report().parked.ended, 1);
        assert_eq!(scene.clients[1].outcome(id), None, "its ERROR waits");
        let census = scene.owner.peer_census(PeerId(1));
        assert!(
            census.active == 0 && census.draining >= 1,
            "the ERROR keeps the follower's request draining: {census:?}"
        );
        scene.nets[1].borrow_mut().set_faults(0, Faults::default());
        let (outcome, _) = collect(&mut scene, 1, id);
        assert_eq!(outcome, Some(Outcome::Missing));
    });
}

/// A session replacement retires its parked GETs and detaches their
/// followers, and the producer still publishes; a stale GET of an older
/// generation changes nothing.
#[test]
fn a_retired_session_detaches_its_followers_and_a_stale_get_changes_nothing() {
    scene(&PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let at = request(2, 2);
        let header = scene.get(1, at, NAME);
        scene.inject(1, &header);
        drive(&mut scene, 5);
        assert_eq!(parked(&scene), 1);
        let before = scene.owner.parked_view();
        let stale = scene.get(1, request(2, 1), NAME);
        scene.inject(1, &stale);
        drive(&mut scene, 5);
        assert_eq!(scene.owner.parked_view().entries, before.entries);
        assert_eq!(scene.owner.report().parked.joined, 1);
        scene.reopen(1);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 0);
        assert_eq!(scene.owner.report().parked.detached, 1);
        finish_upload(&mut scene, put, &object);
        assert_eq!(uploaded(&mut scene, put), Some(UploadOutcome::Published));
    });
}

/// With joins off, a GET of a key under upload ends `Missing` at once.
#[test]
fn joins_off_answer_a_missing_get_at_once() {
    let config = OwnerConfig {
        follow: FollowConfig::OFF,
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let (_put, _object) = open_upload(&mut scene);
        let id = get(&mut scene, 1, 30_000_000);
        let (outcome, _) = collect(&mut scene, 1, id);
        assert_eq!(outcome, Some(Outcome::Missing));
        assert_eq!(scene.owner.report().parked.joined, 0);
    });
}

#[test]
fn a_join_short_of_lookup_work_leaves_the_proved_miss() {
    use crate::storage::{LookupError, WorkBudget};
    let storage = crate::storage::owner_fixture::storage(8);
    let miss = {
        let mut reader = storage.register().unwrap();
        let mut budget = WorkBudget::new(1 << 12);
        let refused = reader
            .lookup(&key(NAME), OWNER.lookup_retries, &mut budget)
            .map(|lease| lease.id());
        assert!(matches!(refused, Err(LookupError::Missing)), "{refused:?}");
        (1 << 12) - budget.remaining()
    };
    let config = OwnerConfig {
        lookup_work: miss + 1,
        ..OWNER
    };
    super::put_tests::scene_over(storage, config, &PRINCIPALS, |mut scene| {
        let id = get(&mut scene, 1, 30_000_000);
        let (outcome, _) = collect(&mut scene, 1, id);
        assert_eq!(outcome, Some(Outcome::Missing));
        assert_eq!(scene.owner.report().parked.joined, 0);
    });
}

#[test]
fn a_poisoned_shard_leaves_a_missing_get_at_the_lookups_miss() {
    scene(&PRINCIPALS, |mut scene| {
        crate::storage::owner_fixture::poison_shard(scene.storage);
        let id = get(&mut scene, 1, 30_000_000);
        let (outcome, _) = collect(&mut scene, 1, id);
        assert_eq!(outcome, Some(Outcome::Missing));
        assert_eq!(scene.owner.report().parked.joined, 0);
        assert_eq!(scene.owner.report().defects, 0);
    });
}

/// A parked GET is admitted inside the GET reserve while PUTs hold every
/// PUT cap: peer 0's upload is active and peer 1's, cancelled with its
/// writes held, drains, so the global cap and peer 1's share are full. The
/// GET parks, peer 1's next BEGIN is refused, and once the drain ends and
/// peer 0's upload publishes, the GET starts its read. Peer 1's frames are
/// injected under the session its client opened, and `polls` leave the
/// device untouched so the drain holds.
#[test]
fn a_parked_get_admits_inside_the_get_reserve_while_puts_saturate_their_caps() {
    scene(&PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let other = payload(2 * FRAGMENT, 63);
        let (at, serial) = super::put_tests::ready_upload(&mut scene, &other);
        for index in 0..2 {
            let (header, body) = scene.fragment(at, serial, &other, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(2);
        let stop = scene.frame(1, Kind::PutCancel, at, 5, super::put_tests::cancel(serial));
        scene.inject(1, &stop);
        scene.polls(2);
        let occupancy = scene.owner.put_occupancy();
        assert_eq!(occupancy.live, OWNER.put.puts, "the global PUT cap is full");
        assert_eq!(occupancy.peers, [1, 1], "each peer's PUT cap is full");
        assert_eq!(scene.owner.census().draining, 1, "peer 1's PUT drains");
        let over = scene.frame(1, Kind::PutBegin, request(2, 1), 7, |_| {});
        scene.inject(1, &over);
        let get_at = request(3, 1);
        let header = scene.get(1, get_at, NAME);
        scene.inject(1, &header);
        scene.polls(2);
        let refused: Vec<_> = scene
            .replies(1)
            .iter()
            .filter(|reply| reply.request == request(2, 1))
            .filter_map(super::put_tests::error)
            .collect();
        assert!(refused.contains(&Status::RequestPressure), "{refused:?}");
        assert_eq!(parked(&scene), 1, "the GET parked inside the reserve");
        assert_eq!(scene.owner.census().draining, 1, "beside the draining PUT");
        finish_upload(&mut scene, put, &object);
        assert_eq!(uploaded(&mut scene, put), Some(UploadOutcome::Published));
        assert_eq!(
            scene.owner.report().parked.woke,
            1,
            "the parked GET started its read"
        );
        assert_eq!(parked(&scene), 0);
    });
}

/// A parked GET wakes and reads while every lease credit is held: its
/// acquisition takes the read right alone, as a fresh GET's lookup does, so
/// the full lease limit refuses nothing and the owner counts no defect.
#[test]
fn a_parked_get_wakes_and_reads_with_every_lease_credit_held() {
    let storage = crate::storage::owner_fixture::storage_leasing(2 * OWNER.put.puts as usize);
    super::put_tests::scene_over(storage, OWNER, &PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let id = get(&mut scene, 1, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 1);
        let storage = scene.storage;
        let mut reader = storage.register().unwrap();
        let mut held = Vec::new();
        // Before each turn the test takes every free credit, so each wake
        // visit meets a full lease limit: the publication that frees the
        // publisher's credit runs after the turn's wake pass, and the next
        // turn's fill takes that credit before the pass.
        let mut fill = |held: &mut Vec<_>| {
            loop {
                match reader.lookup(&key(1), 4, &mut crate::storage::WorkBudget::new(1 << 12)) {
                    Ok(lease) => held.push(lease),
                    Err(error) => {
                        assert_eq!(error, crate::storage::LookupError::LeaseLimit);
                        break;
                    }
                }
                assert!(held.len() < 16, "the lease limit bounds the leases");
            }
        };
        finish_upload(&mut scene, put, &object);
        let mut bytes = Vec::new();
        for _ in 0..2_000 {
            fill(&mut held);
            drive(&mut scene, 1);
            while let Some(fragment) = scene.clients[1].take(id) {
                bytes.extend_from_slice(fragment.bytes());
            }
            if scene.clients[1].outcome(id).is_some() {
                break;
            }
        }
        assert_eq!(scene.clients[1].outcome(id), Some(Outcome::Complete));
        assert_eq!(bytes, object);
        assert_eq!(scene.owner.report().defects, 0);
        assert_eq!(scene.owner.report().parked.woke, 1);
        drop(held);
    });
}

/// At the owner's caps, every request slot live and three GETs parked behind
/// one upload, the owner's turns allocate nothing: through parking, the
/// wake passes, the publication, a stretch with the device and the links
/// holding every command and datagram, and the joined reads to their end.
#[test]
fn a_maximum_cap_parked_history_allocates_nothing_after_construction() {
    use crate::sim::round::{Act, round};
    let config = OwnerConfig {
        follow: FollowConfig {
            fill_followers: 3,
            ..OWNER.follow
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let gets = [
            (1, get(&mut scene, 1, 30_000_000)),
            (1, get(&mut scene, 1, 30_000_000)),
        ];
        let own = get(&mut scene, 0, 30_000_000);
        let mut allocations = 0;
        // With `held`, the device and both links stand still: no command
        // completes and no datagram moves while the owner turns.
        let mut turns = |scene: &mut Scene<'_, '_>, count: u64, held: bool| {
            for _ in 0..count {
                let turn = scene.turn;
                let now = turn * 100;
                {
                    let Scene {
                        owner,
                        nets,
                        clients,
                        control,
                        ..
                    } = &mut *scene;
                    let [first, second] = clients;
                    let mut links: Vec<_> = nets
                        .iter()
                        .map(|net| move || net.borrow_mut().advance(turn))
                        .collect();
                    let mut client0 = || {
                        let _ = first.poll(now);
                    };
                    let mut client1 = || {
                        let _ = second.poll(now);
                    };
                    let mut tick = || control.tick(64);
                    let mut poll = || {
                        let before = crate::instrument::allocations();
                        owner.poll(now);
                        allocations += crate::instrument::allocations() - before;
                    };
                    let mut acts = Vec::new();
                    if !held {
                        for link in &mut links {
                            acts.push(Act::new(Actor::Link(0), link));
                        }
                        acts.push(Act::new(Actor::Client(0), &mut client0));
                        acts.push(Act::new(Actor::Client(1), &mut client1));
                        acts.push(Act::new(Actor::Disk(0), &mut tick));
                    }
                    acts.push(Act::new(Actor::Owner(0), &mut poll));
                    round(&mut acts);
                }
                scene.turn += 1;
            }
        };
        turns(&mut scene, 20, false);
        assert_eq!(parked(&scene), 3, "three GETs parked");
        assert_eq!(
            scene.owner.census().live(),
            OWNER.request_slots,
            "every slot live"
        );
        finish_upload(&mut scene, put, &object);
        // Mid-history, with the reads' commands and datagrams in flight, the
        // device and the links hold everything for a stretch of owner turns.
        turns(&mut scene, 30, false);
        let live = scene.owner.census();
        let heap = crate::instrument::live_bytes();
        turns(&mut scene, 40, true);
        assert_eq!(
            scene.owner.census(),
            live,
            "a held stack keeps its requests"
        );
        assert_eq!(crate::instrument::live_bytes(), heap, "and its heap");
        for _ in 0..2_000 {
            turns(&mut scene, 1, false);
            for (reader, id) in gets.iter().copied().chain([(0, own)]) {
                while let Some(fragment) = scene.clients[reader].take(id) {
                    drop(fragment);
                }
            }
            let decided = gets
                .iter()
                .copied()
                .chain([(0, own)])
                .all(|(reader, id)| scene.clients[reader].outcome(id).is_some());
            if decided {
                break;
            }
        }
        for (reader, id) in gets.iter().copied().chain([(0, own)]) {
            assert_eq!(scene.clients[reader].outcome(id), Some(Outcome::Complete));
        }
        assert_eq!(scene.owner.report().parked.woke, 3);
        assert_eq!(allocations, 0, "the owner's turns allocated");
    });
}

/// Client `reader`'s GET of key `name` waiting at most `wait_us`.
fn get_of(scene: &mut Scene<'_, '_>, reader: usize, name: u8, wait_us: u64) -> RequestId {
    let now = scene.turn * 100;
    scene.clients[reader]
        .get(key(name), 0, 1 << 20, now, wait_us)
        .unwrap()
}

/// GETs parked behind an upload in progress are visited in the turn they
/// join and then by no turn until something can end their wait: the
/// upload's fill reports its own departure, so every turn across five check
/// periods visits nothing, and its publication still reaches both followers.
#[test]
fn waiting_turns_visit_no_parked_get() {
    scene(&PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let first = get(&mut scene, 1, 30_000_000);
        let second = get(&mut scene, 1, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 2);
        let turns = 5 * super::parked::CHECK_US / 100;
        for turn in 0..turns {
            drive(&mut scene, 1);
            assert_eq!(
                scene.owner.wake_visits(),
                0,
                "turn {turn} visited a waiting GET"
            );
        }
        finish_upload(&mut scene, put, &object);
        for id in [first, second] {
            let (outcome, bytes) = collect(&mut scene, 1, id);
            assert_eq!((outcome, bytes), (Some(Outcome::Complete), object.clone()));
        }
        assert_eq!(parked(&scene), 0);
    });
}

/// A cancelled parked GET owes a visit to its own entry alone: the turns
/// after the cancel make one visit, which detaches it, and the other
/// follower stays parked until the upload publishes.
#[test]
fn an_ended_request_owes_a_visit_to_its_entry_alone() {
    scene(&PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let first = get(&mut scene, 1, 30_000_000);
        let second = get(&mut scene, 1, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 2);
        scene.clients[1].cancel(first);
        let mut visits = 0;
        for _ in 0..20 {
            drive(&mut scene, 1);
            visits += scene.owner.wake_visits();
        }
        assert_eq!(visits, 1, "the cancel's visit alone");
        assert_eq!(parked(&scene), 1);
        let ends = scene.owner.parked_view().ends;
        assert!(matches!(ends.as_slice(), [(_, End::Detached)]), "{ends:?}");
        finish_upload(&mut scene, put, &object);
        let (outcome, bytes) = collect(&mut scene, 1, second);
        assert_eq!((outcome, bytes), (Some(Outcome::Complete), object));
    });
}

/// A fill's departure owes visits to that fill's followers alone: with one
/// visit a turn and the followers of an upload and of a local fill
/// interleaved by slot, the upload's two followers start their reads in the
/// two turns after its publication while the local fill's stay parked. The
/// local fill then departs outside the owner, and a check within its period
/// finds it, so its followers end `Missing`.
#[test]
fn a_departure_owes_visits_to_its_fills_followers_alone() {
    const LOCAL: u8 = 7;
    let config = OwnerConfig {
        request_slots: 8,
        peer_requests: 4,
        follow: FollowConfig {
            followers: 6,
            fill_followers: 4,
            peer_followers: 4,
            wake: 1,
        },
        ..OWNER
    };
    let storage = crate::storage::owner_fixture::storage_windowed(4, 8);
    super::put_tests::scene_over(storage, config, &PRINCIPALS, |mut scene| {
        let (put, object) = open_upload(&mut scene);
        let local = crate::storage::owner_fixture::reserve(scene.storage, &key(LOCAL), 0, FRAGMENT)
            .expect("a local fill");
        // Each client's GETs take adjacent slots, the first client's first.
        let ids = [(0, NAME), (0, LOCAL), (1, NAME), (1, LOCAL)]
            .map(|(reader, name)| (reader, get_of(&mut scene, reader, name, 30_000_000)));
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 4);
        finish_upload(&mut scene, put, &object);
        let published = (0..2_000)
            .find(|_| {
                drive(&mut scene, 1);
                scene.visible(NAME)
            })
            .expect("the upload published");
        let woke = (1..=4)
            .find(|_| {
                drive(&mut scene, 1);
                scene.owner.report().parked.woke == 2
            })
            .expect("the upload's followers woke");
        assert!(woke <= 2, "woke {woke} turns after turn {published}");
        assert_eq!(parked(&scene), 2, "the local fill's followers stay parked");
        local.abort();
        let turns = super::parked::CHECK_US / 100 + 4;
        let ended = (0..turns).any(|_| {
            drive(&mut scene, 1);
            scene.owner.parked_count() == 0
        });
        assert!(ended, "a check found the local fill's departure");
        for (reader, id) in [ids[1], ids[3]] {
            let (outcome, _) = collect(&mut scene, reader, id);
            assert_eq!(outcome, Some(Outcome::Missing));
        }
        for (reader, id) in [ids[0], ids[2]] {
            let (outcome, bytes) = collect(&mut scene, reader, id);
            assert_eq!((outcome, bytes), (Some(Outcome::Complete), object.clone()));
        }
    });
}

/// Streams `object` into `fill` through the owner while the scene turns,
/// then publishes it through the owner.
fn publish_local<'s, 'm>(
    scene: &mut Scene<'s, 'm>,
    mut fill: crate::storage::WritableFill<'s, 'm, crate::storage::owner_fixture::TestPlatform>,
    object: &[u8],
) {
    let mut taken = 0;
    for _ in 0..2_000 {
        if scene.owner.fill_progress(&fill).is_ready() {
            break;
        }
        let mut budget = crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX);
        if taken < object.len()
            && let Ok(n) = scene
                .owner
                .receive_fill(&mut fill, &object[taken..], &mut budget)
        {
            taken += n;
        }
        drive(scene, 1);
    }
    let mut budget = crate::storage::WorkBudget::new(1 << 12);
    let lease = scene
        .owner
        .publish_fill(fill, u64::MAX, 4, &mut budget)
        .expect("published");
    drop(lease);
}

/// A local fill published through the owner reports its departure: its
/// follower starts its read in the next turn, well inside the check period
/// that a fill departing outside the owner waits for.
#[test]
fn a_local_fill_published_through_the_owner_wakes_its_follower_at_once() {
    const LOCAL: u8 = 7;
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(FRAGMENT, 63);
        let fill =
            crate::storage::owner_fixture::reserve(scene.storage, &key(LOCAL), 0, object.len())
                .expect("a local fill");
        let id = get_of(&mut scene, 1, LOCAL, 30_000_000);
        drive(&mut scene, 10);
        assert_eq!(parked(&scene), 1);
        publish_local(&mut scene, fill, &object);
        assert_eq!(
            scene.owner.parked_view().owed,
            1,
            "the publication owed its follower a visit"
        );
        drive(&mut scene, 1);
        assert_eq!(
            scene.owner.report().parked.woke,
            1,
            "the publication woke its follower in the next turn"
        );
        let (outcome, bytes) = collect(&mut scene, 1, id);
        assert_eq!((outcome, bytes), (Some(Outcome::Complete), object));
    });
}

/// The parked table over more distinct fills than it tracks, with real
/// followers: while the fifth fill's follower is untracked, a due check and
/// any departure owe every entry a visit; once every entry's fill is
/// tracked, a departure owes its own fill's follower alone. The due set and
/// the tracking stay consistent with the entries through every park, visit
/// and take.
#[test]
fn the_parked_table_owes_every_entry_for_a_fill_it_does_not_track() {
    use super::parked::{CHECK_US, Entry, Parked};
    use crate::storage::WorkBudget;
    use crate::storage::owner_fixture::{TestPlatform, reserve, storage_filling};
    const FILLS: u8 = 5;
    let storage = storage_filling(8, usize::from(FILLS));
    let fills: Vec<_> = (0..FILLS)
        .map(|at| reserve(&storage, &key(10 + at), 0, FRAGMENT).expect("a local fill"))
        .collect();
    let follow = FollowConfig {
        followers: 8,
        fill_followers: 8,
        peer_followers: 8,
        wake: 1,
    };
    let mut parked = Parked::<TestPlatform>::new(follow, 8, 1);
    let ids: Vec<_> = (0..FILLS)
        .map(|at| {
            let follower = storage
                .join_fill(&key(10 + at), 8, 4, &mut WorkBudget::new(1 << 12))
                .expect("a follower");
            let request = RequestId::from_wire(request(u16::from(at), 1));
            let entry = Entry {
                request,
                peer: PeerId(0),
                follower,
            };
            parked.park(entry, |_| false);
            parked.check_tracking().unwrap();
            usize::from(request.slot())
        })
        .collect();
    let fill_of = |slot: usize, parked: &Parked<'_, TestPlatform>| {
        let follower = &parked.entry(slot).follower;
        (follower.shard(), follower.serial())
    };
    let fills_of: Vec<_> = ids.iter().map(|&slot| fill_of(slot, &parked)).collect();
    // Every pass visits what is owed, one entry at a time, and returns the visited slots.
    let pass = |parked: &mut Parked<'_, TestPlatform>, now_us: u64| {
        let mut visited = Vec::new();
        for _ in 0..2 * FILLS {
            parked.begin_pass(now_us, Ok(()));
            while parked.check().is_some() {}
            parked.begin_visits();
            visited.extend(std::iter::from_fn(|| parked.visit()));
            parked.check_tracking().unwrap();
        }
        visited.sort_unstable();
        visited
    };
    assert_eq!(pass(&mut parked, 0), ids, "each join owed its own visit");
    assert!(!parked.has_work(CHECK_US - 1, Ok(())));
    assert_eq!(
        pass(&mut parked, CHECK_US),
        ids,
        "a due check owes every entry"
    );
    parked.departed(fills_of[4]);
    assert_eq!(
        pass(&mut parked, CHECK_US + 1),
        ids,
        "an untracked fill owes every entry"
    );
    parked.departed(fills_of[0]);
    assert_eq!(
        pass(&mut parked, CHECK_US + 2),
        ids,
        "a tracked fill owes every entry while one is untracked"
    );
    drop(parked.take(ids[4]));
    parked.check_tracking().unwrap();
    parked.departed(fills_of[1]);
    assert_eq!(
        pass(&mut parked, CHECK_US + 3),
        ids[1..2],
        "with every fill tracked a fill owes its follower alone"
    );
    for &slot in ids[..4].iter().rev() {
        drop(parked.take(slot));
        parked.check_tracking().unwrap();
    }
    assert!(parked.is_empty());
    assert!(
        !parked.has_work(10 * CHECK_US, Ok(())),
        "an empty table watches nothing"
    );
    drop(fills);
}

/// A due check of a fill the owner may not see depart runs while visits
/// stay owed on every pass, before them and within the allowance, and the
/// owed visits still progress: at one visit a turn the check and the visits
/// alternate, and at two each takes one, also when every turn spans a check
/// period and checks run back to back. A steady stream of owed visits thus
/// delays such a departure by at most a check period and its turns.
#[test]
fn a_due_check_runs_while_visits_stay_owed() {
    use super::parked::{CHECK_US, Entry, Parked};
    use crate::storage::WorkBudget;
    use crate::storage::owner_fixture::{TestPlatform, reserve, storage_filling};
    let storage = storage_filling(8, 2);
    let fills: Vec<_> = [10, 11]
        .map(|name| reserve(&storage, &key(name), 0, FRAGMENT).expect("a local fill"))
        .into();
    for (wake, step) in [(1, 100), (2, 100), (1, CHECK_US), (2, CHECK_US)] {
        let follow = FollowConfig {
            followers: 8,
            fill_followers: 8,
            peer_followers: 8,
            wake,
        };
        let mut parked = Parked::<TestPlatform>::new(follow, 8, 1);
        for (at, name) in [(0, 10), (1, 11)] {
            let follower = storage
                .join_fill(&key(name), 8, 4, &mut WorkBudget::new(1 << 12))
                .expect("a follower");
            let request = RequestId::from_wire(request(at, 1));
            let entry = Entry {
                request,
                peer: PeerId(0),
                follower,
            };
            let reported = name == 10 && step == 100;
            parked.park(entry, |_| reported);
        }
        let (mut checked, mut visited) = (Vec::new(), 0);
        let turns = 2 * CHECK_US / 100;
        for turn in 0..=turns {
            // The first fill's follower is owed a visit on every pass.
            parked.owe(0);
            parked.begin_pass(turn * step, Ok(()));
            checked.extend(std::iter::from_fn(|| parked.check()).map(|slot| (turn, slot)));
            parked.begin_visits();
            visited += std::iter::from_fn(|| parked.visit()).count() as u64;
            assert!(parked.visits() <= wake, "wake {wake} turn {turn}");
            parked.check_tracking().unwrap();
        }
        if step == 100 {
            // A check that meets a pass whose share is zero lands one turn later.
            let period = CHECK_US / 100;
            assert_eq!(checked.len(), 3, "wake {wake}: {checked:?}");
            for (at, &(turn, slot)) in checked.iter().enumerate() {
                let due = at as u64 * period;
                assert!(
                    slot == 1 && (due..=due + 1).contains(&turn),
                    "wake {wake}: the unreported fill is checked every period: {checked:?}"
                );
            }
        } else {
            assert!(
                checked.len() as u64 >= turns / 2,
                "wake {wake}: both fills are checked as each check falls due: {checked:?}"
            );
        }
        assert!(
            visited >= turns / 2,
            "wake {wake} step {step}: the owed visits progress, {visited} in {turns} turns"
        );
    }
    drop(fills);
}
