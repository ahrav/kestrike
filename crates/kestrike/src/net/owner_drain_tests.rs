//! The owner's admission stages for a planned exit. [`DrainStage::Fills`] refuses PUT BEGIN `OwnerUnavailable`,
//! ends every upload that has not published and keeps a published fill's acknowledgment, while GET hits and
//! INVALIDATE continue and an INVALIDATE is acknowledged only after its coverage page write commits.
//! [`DrainStage::Mutations`] also refuses INVALIDATE and every other membership change, maintenance removals
//! included, and drops the held INVALIDATEs unacknowledged, while GET hits continue. [`Owner::resume`] reopens
//! admission only before the withdrawal, and the report entry's exit status follows the planned request.
//!
//! [`Owner::resume`]: super::owner::Owner::resume

use std::cell::Cell;

use super::frame::{Header, Kind, Status};
use super::owner::DrainStage;
use super::owner_entry_tests::{active, entry, viewed};
use super::owner_tenure_tests::{observe, shard_at, token};
use super::owner_tests::{PRINCIPALS, key, payload};
use super::put_tests::{
    Scene, error, fenced_coverage, pin_holes, prepare, ready_upload, ready_upload_from, request,
    run_wait_scene, scene, send_all, upload_within, versions,
};
use crate::failover::report::{ExitOperation, ExitStatus, Observed, Resume};
use crate::failover::serving::{Cause, Event};
use crate::net::PeerId;
use crate::storage::page_coverage::{Cover, Withdraw, page_of};
use crate::storage::store::sim::{MemLog, Shared};
use crate::storage::store::{Client, Key};
use crate::storage::store_tests::{record, shard};
use crate::storage::{InvalidateError, WorkBudget};

/// A planted defect that a control runs a stage test against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    /// The BEGIN admission check admits a PUT BEGIN in either drain stage.
    FillsAdmitted,
    /// `Owner::drain` enters `DrainStage::Fills` when asked for `DrainStage::Mutations`, so the held INVALIDATEs
    /// stay held and their page write acknowledges them.
    MutationsAdmitted,
    /// The read admission check refuses a GET `OwnerUnavailable` in either drain stage.
    HitsRefused,
    /// `ServeCore::put_results_queued` reads every queued PUT RESULT, a replay of a retained terminal included.
    ReplaysCounted,
}

thread_local! {
    static PLANTED: Cell<Option<Plant>> = const { Cell::new(None) };
}

/// Whether the running test planted `plant`.
pub(crate) fn planted(plant: Plant) -> bool {
    PLANTED.with(Cell::get) == Some(plant)
}

pub(crate) fn with_plant<T>(plant: Plant, f: impl FnOnce() -> T) -> T {
    PLANTED.with(|cell| cell.set(Some(plant)));
    let out = f();
    PLANTED.with(|cell| cell.set(None));
    out
}

/// The status a refused PUT BEGIN answers, or `None` when the owner grants it authority.
fn begin_status(scene: &mut Scene<'_, '_>, slot: u16, name: u8) -> Option<Status> {
    let begin = scene.frame(1, Kind::PutBegin, request(slot, 1), name, |_| {});
    let reply = scene.one(1, &begin);
    match reply.kind {
        Kind::PutAuthority => None,
        Kind::PutError => error(&reply),
        kind => panic!("a BEGIN answered {kind:?}"),
    }
}

/// Whether a client GET of the scene's preloaded object completes with its bytes.
fn hit(scene: &mut Scene<'_, '_>) -> bool {
    let (outcome, bytes) = scene.read(0, 1, 0);
    outcome == Some(super::fetch::Outcome::Complete) && bytes == payload(1000, 1)
}

type Lane = Client<Shared, MemLog>;

/// Installs a fencing over a fresh store seeded under the owner's tenure.
fn fenced(scene: &mut Scene<'_, '_>) -> (Shared, Lane) {
    let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
    let (fencing, client) = fenced_coverage(&store, scene.owner.tenure());
    scene.owner.install_coverage(fencing).unwrap();
    (store, client)
}

fn commits(store: &Shared, name: u8) -> usize {
    let page = Key::Page(shard(), page_of(&key(name), record().pages));
    store.0.borrow().commit_count(&page)
}

/// Sends an authenticated INVALIDATE of key `name` over `[3, 5]` from client 1 at slot `slot`.
fn wire_invalidate(scene: &mut Scene<'_, '_>, slot: u16, name: u8) -> Header {
    let frame = scene.frame(1, Kind::Invalidate, request(slot, 1), name, |header| {
        header.allocation = 3;
        header.offset = 5;
    });
    scene.inject(1, &frame);
    scene.turns(4);
    frame
}

/// The INVALIDATED frames the owner sent toward client 1 since the last read of its link, as their requests.
fn invalidated(scene: &mut Scene<'_, '_>) -> Vec<u64> {
    let sent = scene.sent(1);
    let acknowledged = sent.iter().filter(|frame| frame.kind == Kind::Invalidated);
    acknowledged.map(|frame| frame.request).collect()
}

fn stage_one_failures() -> Vec<String> {
    let mut broken = Vec::new();
    scene(&PRINCIPALS, |mut scene| {
        scene.owner.drain(DrainStage::Fills, 0);
        let refused = begin_status(&mut scene, 1, 5);
        if refused != Some(Status::OwnerUnavailable) {
            broken.push(format!("a BEGIN in stage 1 answered {refused:?}"));
        }
        if !hit(&mut scene) {
            broken.push("a GET hit in stage 1 was not served".into());
        }
        let (store, mut client) = fenced(&mut scene);
        let before = commits(&store, 1);
        let frame = wire_invalidate(&mut scene, 2, 1);
        if scene.visible(1) {
            broken.push("stage 1 kept a key its INVALIDATE removes".into());
        }
        if !invalidated(&mut scene).is_empty() {
            broken.push("stage 1 acknowledged an INVALIDATE before its page write".into());
        }
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        let written = commits(&store, 1) - before;
        scene.turns(4);
        let sent = invalidated(&mut scene);
        if (acknowledged, written, sent.clone())
            != (vec![(key(1), versions(3, 5))], 1, vec![frame.request])
        {
            broken.push(format!(
                "stage 1 acknowledged {sent:?} after {written} page commits"
            ));
        }
    });
    broken
}

/// In stage 1 a PUT BEGIN is refused `OwnerUnavailable`, a GET hit returns the stored bytes, and a wire
/// INVALIDATE removes its key at once and is answered INVALIDATED for its request only after one page commit.
#[test]
fn stage_one_refuses_a_begin_and_serves_hits_and_invalidates() {
    assert_eq!(stage_one_failures(), Vec::<String>::new());
}

/// FP-HAND-05: a stage 1 that admits a PUT BEGIN fails the stage test on the BEGIN check alone.
#[test]
fn control_a_stage_one_admitting_a_begin_fails_the_stage_test() {
    let broken = with_plant(Plant::FillsAdmitted, stage_one_failures);
    assert_eq!(
        broken,
        ["a BEGIN in stage 1 answered None"],
        "FP-HAND-05: the planted stage 1 grants PUT authority: {broken:?}"
    );
}

/// A ready upload from client 1 and an upload at its BEGIN from client 0 each end with one `OwnerUnavailable` PUT
/// ERROR for their own requests and no PUT RESULT, and their keys stay invisible. A fill published before the drain,
/// whose first PUT RESULT was lost, is answered PUT RESULT again in stage 1 for its request and allocation.
#[test]
fn stage_one_ends_an_unpublished_fill_and_keeps_a_published_one() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(3, 1);
        let serial = scene.begin(1, at, 6);
        let header = scene.frame(1, Kind::PutPrepare, at, 6, prepare(serial, 0, 60_000));
        scene.inject(1, &header);
        scene.turns(4);
        assert!(scene.visible(6), "the first fill published");
        let lost = scene.replies(1);
        assert!(
            lost.iter().any(|reply| reply.kind == Kind::PutResult),
            "the published fill's first PUT RESULT, which the link drops"
        );
        let pending = vec![0; 2 * super::geometry::FRAGMENT_LEN as usize];
        let (ready, _) = ready_upload(&mut scene, &pending);
        let begun = request(2, 1);
        let _ = scene.begin(0, begun, 7);
        scene.owner.drain(DrainStage::Fills, scene.turn * 100);
        let resent = scene.frame(1, Kind::PutPrepare, at, 6, prepare(serial, 0, 60_000));
        scene.inject(1, &resent);
        scene.turns(20);
        let replies = scene.replies(1);
        let ended: Vec<_> = (replies.iter())
            .filter_map(|reply| error(reply).map(|status| (reply.request, status)))
            .collect();
        assert_eq!(ended, [(ready, Status::OwnerUnavailable)], "{replies:?}");
        let results: Vec<_> = (replies.iter())
            .filter(|reply| reply.kind == Kind::PutResult)
            .map(|reply| (reply.request, reply.allocation))
            .collect();
        assert_eq!(
            results,
            [(at, serial)],
            "the published fill's result replays"
        );
        let other = scene.replies(0);
        let ended: Vec<_> = (other.iter())
            .filter_map(|reply| error(reply).map(|status| (reply.request, status)))
            .collect();
        assert_eq!(ended, [(begun, Status::OwnerUnavailable)], "{other:?}");
        assert!(other.iter().all(|reply| reply.kind != Kind::PutResult));
        assert!(
            !scene.visible(5) && !scene.visible(7),
            "the unpublished fills ended"
        );
        assert!(scene.visible(6), "the published fill stays");
        assert_eq!(scene.owner.put_occupancy().live, 0);
        assert_eq!(scene.owner.draining(), Some(DrainStage::Fills));
    });
}

/// A fill that publishes while sends toward its client are blocked has its PUT RESULT queued and unsent when the
/// drain starts; once sends resume, stage 1 delivers exactly that result for its request and allocation, with no
/// frame resent.
#[test]
fn stage_one_sends_a_published_fill_s_queued_result() {
    use super::link::Faults;
    scene(&PRINCIPALS, |mut scene| {
        let at = request(3, 1);
        let serial = scene.begin(1, at, 6);
        let blocked = Faults {
            would_block: 100,
            ..Faults::default()
        };
        scene.nets[1].borrow_mut().set_faults(0, blocked);
        let header = scene.frame(1, Kind::PutPrepare, at, 6, prepare(serial, 0, 60_000));
        scene.inject(1, &header);
        scene.turns(4);
        assert!(scene.visible(6), "the fill published");
        assert!(
            scene
                .replies(1)
                .iter()
                .all(|reply| reply.kind != Kind::PutResult),
            "the result is still queued"
        );
        scene.owner.drain(DrainStage::Fills, scene.turn * 100);
        scene.nets[1].borrow_mut().set_faults(0, Faults::default());
        scene.turns(8);
        let results: Vec<_> = (scene.replies(1).iter())
            .filter(|reply| reply.kind == Kind::PutResult)
            .map(|reply| (reply.request, reply.allocation))
            .collect();
        assert_eq!(results, [(at, serial)]);
        assert_eq!(scene.owner.draining(), Some(DrainStage::Fills));
    });
}

/// RESULT-BEFORE-WITHDRAWAL's predicate: `Owner::put_results_queued` reads true while a published fill's PUT RESULT
/// waits behind blocked sends, during the drain as before it, and false once the result is sent.
#[test]
fn a_queued_put_result_reads_queued_until_it_is_sent() {
    use super::link::Faults;
    scene(&PRINCIPALS, |mut scene| {
        let at = request(3, 1);
        let serial = scene.begin(1, at, 6);
        assert!(!scene.owner.put_results_queued());
        let blocked = Faults {
            would_block: 100,
            ..Faults::default()
        };
        scene.nets[1].borrow_mut().set_faults(0, blocked);
        let header = scene.frame(1, Kind::PutPrepare, at, 6, prepare(serial, 0, 60_000));
        scene.inject(1, &header);
        scene.turns(4);
        assert!(scene.visible(6), "the fill published");
        assert!(
            scene.owner.put_results_queued(),
            "the result waits behind blocked sends"
        );
        scene.owner.drain(DrainStage::Fills, scene.turn * 100);
        assert!(
            scene.owner.put_results_queued(),
            "the drain keeps the queued result"
        );
        scene.nets[1].borrow_mut().set_faults(0, Faults::default());
        scene.turns(8);
        assert!(
            (scene.replies(1).iter()).any(|reply| reply.kind == Kind::PutResult),
            "the result was sent"
        );
        assert!(!scene.owner.put_results_queued());
    });
}

/// A replay of a retained terminal stays out of the predicate: a fill publishes and its PUT RESULT is sent, then
/// sends toward its client block, the owner drains fills and the client resends its PREPARE. The replayed PUT
/// RESULT waits in the ring and `Owner::put_results_queued` reads false; once sends resume the replay goes out.
/// Returns each check that failed.
fn replay_during_the_drain() -> Vec<String> {
    use super::link::Faults;
    let mut failures = Vec::new();
    scene(&PRINCIPALS, |mut scene| {
        let at = request(3, 1);
        let serial = scene.begin(1, at, 6);
        let header = scene.frame(1, Kind::PutPrepare, at, 6, prepare(serial, 0, 60_000));
        scene.inject(1, &header);
        scene.turns(4);
        let first = scene.replies(1);
        if !(scene.visible(6) && first.iter().any(|reply| reply.kind == Kind::PutResult)) {
            failures.push(format!("the fill's first result was not sent: {first:?}"));
        }
        if scene.owner.put_results_queued() {
            failures.push("a sent result reads queued".to_owned());
        }
        let blocked = Faults {
            would_block: 100,
            ..Faults::default()
        };
        scene.nets[1].borrow_mut().set_faults(0, blocked);
        scene.owner.drain(DrainStage::Fills, scene.turn * 100);
        let resent = scene.frame(1, Kind::PutPrepare, at, 6, prepare(serial, 0, 60_000));
        scene.inject(1, &resent);
        scene.turns(4);
        if scene.owner.put_results_queued() {
            failures.push("RESULT-BEFORE-WITHDRAWAL: a replayed terminal reads queued".to_owned());
        }
        scene.nets[1].borrow_mut().set_faults(0, Faults::default());
        scene.turns(8);
        let replayed = (scene.replies(1).iter())
            .filter(|reply| reply.kind == Kind::PutResult)
            .count();
        if replayed != 1 {
            failures.push(format!("{replayed} replayed results reached the client"));
        }
    });
    failures
}

#[test]
fn a_replayed_put_result_stays_out_of_the_queued_reading() {
    let failures = replay_during_the_drain();
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn control_a_reading_that_counts_replays_fails_the_replay_test() {
    let failures = with_plant(Plant::ReplaysCounted, replay_during_the_drain);
    assert_eq!(
        failures,
        ["RESULT-BEFORE-WITHDRAWAL: a replayed terminal reads queued"]
    );
}

/// A planned withdrawal sends no queued reply: a fill publishes while sends toward its client are blocked, the owner
/// drains both stages and withdraws for `Cause::Planned` before sends resume, and the queued PUT RESULT stays unsent
/// (ResponseInIncarnation). The published key stays visible, so the object is the next tenure's to serve.
#[test]
fn a_planned_withdrawal_leaves_a_published_fill_s_queued_result_unsent() {
    use super::link::Faults;
    scene(&PRINCIPALS, |mut scene| {
        let at = request(3, 1);
        let serial = scene.begin(1, at, 6);
        let blocked = Faults {
            would_block: 100,
            ..Faults::default()
        };
        scene.nets[1].borrow_mut().set_faults(0, blocked);
        let header = scene.frame(1, Kind::PutPrepare, at, 6, prepare(serial, 0, 60_000));
        scene.inject(1, &header);
        scene.turns(4);
        assert!(scene.visible(6), "the fill published");
        scene.owner.drain(DrainStage::Fills, scene.turn * 100);
        scene.turns(2);
        scene.owner.drain(DrainStage::Mutations, scene.turn * 100);
        scene.turns(2);
        let withdraw = Event::Withdraw(Cause::Planned);
        scene.owner.authority_event(withdraw, scene.turn * 100);
        scene.nets[1].borrow_mut().set_faults(0, Faults::default());
        scene.turns(8);
        let results = (scene.replies(1).iter())
            .filter(|reply| reply.kind == Kind::PutResult)
            .count();
        assert_eq!(results, 0, "a PUT RESULT sent after the withdrawal");
        assert!(scene.visible(6), "the published key stays visible");
    });
}

/// An upload whose every fragment arrived, with its device writes still outstanding, ends at the drain: once the
/// writes return, the upload has sent one `OwnerUnavailable` PUT ERROR and no PUT RESULT, its key stays invisible
/// and its record is released. The same writes without the drain publish the key.
#[test]
fn stage_one_ends_an_upload_whose_writes_are_outstanding() {
    for drained in [true, false] {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(2 * super::geometry::FRAGMENT_LEN as usize, 41);
            let (at, serial) = ready_upload(&mut scene, &object);
            let _ = send_all(&mut scene, at, serial, &object, 0..2);
            if drained {
                scene.owner.drain(DrainStage::Fills, scene.turn * 100);
            }
            scene.turns(40);
            let replies = scene.replies(1);
            let errors: Vec<_> = replies.iter().filter_map(error).collect();
            let results = replies.iter().filter(|reply| reply.kind == Kind::PutResult);
            if drained {
                assert_eq!(errors, [Status::OwnerUnavailable], "{replies:?}");
                assert_eq!(results.count(), 0, "the ended upload sends no result");
                assert!(!scene.visible(5), "the ended upload stays invisible");
                assert_eq!(scene.owner.put_occupancy().live, 0);
            } else {
                assert_eq!(results.count(), 1, "{replies:?}");
                assert!(scene.visible(5), "the twin without a drain publishes");
            }
        });
    }
}

/// A publication that unwound leaves its upload with no stage. The drain ends it `UnknownOutcome`, both in the PUT
/// ERROR and in the retained terminal a resent frame replays for its request and serial, while a ready upload of the
/// other client ends `OwnerUnavailable`. The poisoned owner refuses a resume and keeps its stage.
#[test]
fn stage_one_ends_an_unwound_publication_unknown() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(super::geometry::FRAGMENT_LEN as usize, 18);
        let (at, serial) = upload_within(&mut scene, &object, 20);
        let pending = vec![0; 2 * super::geometry::FRAGMENT_LEN as usize];
        let ready = request(2, 1);
        let _ = ready_upload_from(&mut scene, 0, ready, 7, &pending);
        let (header, body) = scene.fragment(at, serial, &object, 0);
        crate::storage::owner_fixture::cut_next_publication();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scene.inject_edited(1, &header, &body, |_| {});
            scene.turns(10);
        }));
        assert!(unwound.is_err());
        scene.owner.drain(DrainStage::Fills, scene.turn * 100);
        scene.turns(4);
        let replies = scene.replies(1);
        let errors: Vec<_> = replies.iter().filter_map(error).collect();
        assert_eq!(errors, [Status::UnknownOutcome], "{replies:?}");
        let resent = scene.frame(
            1,
            Kind::PutPrepare,
            at,
            5,
            prepare(serial, object.len() as u32, 60_000),
        );
        scene.inject(1, &resent);
        scene.turns(4);
        let replayed: Vec<_> = (scene.replies(1).iter())
            .filter_map(|reply| {
                error(reply).map(|status| (reply.request, reply.allocation, status))
            })
            .collect();
        assert_eq!(
            replayed,
            [(at, serial, Status::UnknownOutcome)],
            "the retained terminal"
        );
        let other: Vec<_> = scene.replies(0).iter().filter_map(error).collect();
        assert_eq!(other, [Status::OwnerUnavailable]);
        assert!(scene.owner.poisoned() && !scene.owner.lost());
        assert!(
            !scene.owner.resume(Resume::Cut),
            "a poisoned owner stays drained"
        );
        assert_eq!(scene.owner.draining(), Some(DrainStage::Fills));
    });
}

fn stage_two_failures() -> Vec<String> {
    let mut broken = Vec::new();
    scene(&PRINCIPALS, |mut scene| {
        let (store, mut client) = fenced(&mut scene);
        let mut budget = WorkBudget::new(1 << 12);
        (scene.owner)
            .invalidate_interval(&key(5), versions(3, 5), 4, &mut budget)
            .unwrap();
        let local = scene.owner.held_invalidations();
        let held = wire_invalidate(&mut scene, 2, 6);
        if (local, scene.owner.held_invalidations()) != (1, 2) {
            broken.push("setup: the local and wire INVALIDATEs were not both held".into());
        }
        let before = (commits(&store, 5), commits(&store, 6));
        scene.owner.drain(DrainStage::Mutations, scene.turn * 100);
        if scene.owner.held_invalidations() != 0 {
            broken.push("stage 2 kept a held INVALIDATE".into());
        }
        let mut budget = WorkBudget::new(1 << 12);
        let refused = (scene.owner).invalidate_interval(&key(1), versions(1, 1), 4, &mut budget);
        if refused.err() != Some(InvalidateError::Closed) || !scene.visible(1) {
            broken.push(format!("stage 2 took an INVALIDATE: {refused:?}"));
        }
        let mut budget = WorkBudget::new(1 << 12);
        let removed = scene.owner.invalidate(&key(1), 4, &mut budget);
        if removed.as_ref().err() != Some(&InvalidateError::Closed) || !scene.visible(1) {
            broken.push(format!("stage 2 removed a key in RAM: {:?}", removed.err()));
        }
        let late = wire_invalidate(&mut scene, 3, 1);
        if !scene.visible(1) || scene.owner.held_invalidations() != 0 {
            broken.push("stage 2 took a wire INVALIDATE".into());
        }
        if !hit(&mut scene) {
            broken.push("a GET hit in stage 2 was not served".into());
        }
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        if !acknowledged.is_empty() {
            broken.push(format!(
                "stage 2 acknowledged held INVALIDATEs {acknowledged:?}"
            ));
        }
        assert!(scene.owner.resume(Resume::Cut));
        let mut resumed = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut resumed, 0)
            .unwrap();
        scene.turns(4);
        let sent = invalidated(&mut scene);
        if !resumed.is_empty() {
            broken.push(format!(
                "the resume acknowledged dropped INVALIDATEs {resumed:?}"
            ));
        }
        let written = (commits(&store, 5), commits(&store, 6));
        if written != before {
            broken.push(format!("stage 2 committed pages {before:?} to {written:?}"));
        }
        if sent
            .iter()
            .any(|at| [held.request, late.request].contains(at))
        {
            broken.push(format!("stage 2 answered INVALIDATED {sent:?}"));
        }
    });
    broken
}

/// In stage 2 the held INVALIDATEs, local and wire, are dropped on entry, before any coverage call, and stay
/// unacknowledged with no page commit and no INVALIDATED, also after a resume and two coverage turns. A new
/// INVALIDATE, local, RAM-only or wire, is refused with the resident key kept, and a GET hit returns the stored bytes.
#[test]
fn stage_two_acknowledges_no_invalidate_and_serves_hits() {
    assert_eq!(stage_two_failures(), Vec::<String>::new());
}

/// ACK-ON-COMMIT: a stage 2 that stays in stage 1 keeps the held INVALIDATEs and acknowledges them by their page
/// writes, which fails the stage test.
#[test]
fn control_a_stage_two_acknowledging_an_invalidate_fails_the_stage_test() {
    let broken = with_plant(Plant::MutationsAdmitted, stage_two_failures);
    assert!(
        broken
            .iter()
            .any(|failure| failure.starts_with("stage 2 acknowledged held INVALIDATEs [")),
        "ACK-ON-COMMIT: the planted stage 2 acknowledged no held INVALIDATE: {broken:?}"
    );
}

/// The first key above 1 whose coverage page differs from key `name`'s.
fn on_another_page(name: u8) -> u8 {
    let page = |name| page_of(&key(name), record().pages);
    (2..=u8::MAX)
        .find(|&other| page(other) != page(name))
        .unwrap()
}

/// When the reply of a coverage write in flight across `drain(Mutations)` meets the owner after the resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// In stage 2, with no resume.
    Draining,
    /// After the resume, before any later coverage write starts.
    Resumed,
    /// After the resume, while the coverage write of an entry held after it is in flight.
    LaterWriteInFlight,
    /// After the resume, once the coverage writes of the entries held after it have started.
    AfterLaterWrites,
}

/// A coverage write in flight across `drain(Mutations)` commits, and its reply acknowledges nothing and sends no
/// INVALIDATED. A coverage call in stage 2 starts no write. After the resume the old reply acknowledges neither the
/// entry held on another page nor the retry of the old write's key and interval. Before a later write starts,
/// `cover_end` returns `Done` for the old reply and acknowledges nothing. Once a later write starts, `cover_end`
/// refuses the old reply `Unpaired`, while that write is in flight and after it ends. Each later entry's own page
/// commit acknowledges that entry. Only the retry's request receives INVALIDATED.
#[test]
fn a_coverage_write_in_flight_across_a_drain_acknowledges_nothing() {
    for order in [
        Reply::Draining,
        Reply::Resumed,
        Reply::LaterWriteInFlight,
        Reply::AfterLaterWrites,
    ] {
        scene(&PRINCIPALS, |mut scene| {
            let (store, mut client) = fenced(&mut scene);
            let held = wire_invalidate(&mut scene, 2, 5);
            let other = on_another_page(5);
            let before = (commits(&store, 5), commits(&store, other));
            let now = scene.turn * 100;
            let write = scene.owner.cover_begin(None, now).unwrap().unwrap();
            let reply = write.run(&mut client);
            assert_eq!(
                commits(&store, 5),
                before.0 + 1,
                "{order:?}: the old write committed"
            );
            scene.owner.drain(DrainStage::Mutations, now);
            assert_eq!(scene.owner.held_invalidations(), 0);
            assert!(
                scene.owner.cover_begin(None, now).unwrap().is_none(),
                "stage 2 starts no write"
            );
            let mut retry = None;
            if order != Reply::Draining {
                assert!(scene.owner.resume(Resume::Cut));
                let mut budget = WorkBudget::new(1 << 12);
                (scene.owner)
                    .invalidate_interval(&key(other), versions(3, 5), 4, &mut budget)
                    .unwrap();
                retry = Some(wire_invalidate(&mut scene, 3, 5));
            }
            let mut acknowledged = Vec::new();
            let mut reply = Some(reply);
            if order == Reply::LaterWriteInFlight {
                let later = scene.owner.cover_begin(None, now).unwrap();
                let later = later.expect("a later write starts");
                let refused = scene
                    .owner
                    .cover_end(reply.take().unwrap(), &mut acknowledged, now);
                assert!(
                    acknowledged.is_empty(),
                    "ACK-ON-COMMIT: the old reply acknowledged {acknowledged:?} before the page commit of the \
                     write in flight on page {}",
                    later.page()
                );
                assert!(matches!(refused, Err(Withdraw::Unpaired)), "{refused:?}");
                drop(later);
            }
            if matches!(order, Reply::LaterWriteInFlight | Reply::AfterLaterWrites) {
                scene
                    .owner
                    .cover_pending(&mut client, &mut acknowledged, now)
                    .unwrap();
                assert_eq!(
                    acknowledged,
                    [(key(other), versions(3, 5))],
                    "the other page's own commit; the retry's write met the old commit and rebased"
                );
                assert_eq!(commits(&store, other), before.1 + 1);
                assert_eq!(commits(&store, 5), before.0 + 1);
            }
            if let Some(reply) = reply {
                let ended = scene.owner.cover_end(reply, &mut acknowledged, now);
                if order == Reply::AfterLaterWrites {
                    assert!(matches!(ended, Err(Withdraw::Unpaired)), "{ended:?}");
                    assert_eq!(acknowledged, [(key(other), versions(3, 5))]);
                } else {
                    assert!(matches!(ended, Ok(Cover::Done)), "{order:?}: {ended:?}");
                    assert!(acknowledged.is_empty(), "{order:?}: {acknowledged:?}");
                }
            }
            scene.turns(4);
            assert!(
                !invalidated(&mut scene).contains(&held.request),
                "{order:?}"
            );
            if let Some(retry) = retry {
                if order == Reply::Resumed {
                    assert_eq!(scene.owner.held_invalidations(), 2, "the new entries wait");
                    assert_eq!(commits(&store, other), before.1);
                }
                assert_eq!(commits(&store, 5), before.0 + 1);
                scene
                    .owner
                    .cover_pending(&mut client, &mut acknowledged, now)
                    .unwrap();
                acknowledged.sort();
                let mut expected = vec![(key(5), versions(3, 5)), (key(other), versions(3, 5))];
                expected.sort();
                assert_eq!(acknowledged, expected, "{order:?}");
                assert_eq!(commits(&store, other), before.1 + 1, "its own page commit");
                assert_eq!(
                    commits(&store, 5),
                    before.0 + 2,
                    "the retry's own page commit"
                );
                scene.turns(4);
                assert_eq!(
                    invalidated(&mut scene),
                    [retry.request],
                    "only the retry is answered"
                );
            }
        });
    }
}

#[test]
#[should_panic(expected = "ACK-ON-COMMIT: the old reply acknowledged")]
fn control_an_unbound_coverage_reply_acknowledges_a_later_entry_before_its_commit() {
    use crate::storage::page_coverage::UNBOUND_REPLIES;
    UNBOUND_REPLIES.with(|plant| plant.set(true));
    a_coverage_write_in_flight_across_a_drain_acknowledges_nothing();
}

/// A coverage write the size limit rejects, with its reply delivered across `drain(Mutations)`, ends `Unresolved`
/// with no follow-up request and writes no saturated page, with or without a resume between; the same rejection
/// without the drain saturates the page and acknowledges its entry.
#[test]
fn a_rejected_coverage_write_across_a_drain_writes_no_saturated_page() {
    for (drained, resumed) in [(true, false), (true, true), (false, false)] {
        scene(&PRINCIPALS, |mut scene| {
            let (store, mut client) = fenced(&mut scene);
            let page = Key::Page(shard(), page_of(&key(5), record().pages));
            let current = store.0.borrow().current(&page).cloned().unwrap();
            store.0.borrow_mut().limit = current.value.len() + 8;
            let held = wire_invalidate(&mut scene, 2, 5);
            let now = scene.turn * 100;
            let before = commits(&store, 5);
            let write = scene.owner.cover_begin(None, now).unwrap().unwrap();
            let mut reply = write.run(&mut client);
            assert_eq!(
                commits(&store, 5),
                before,
                "the size limit rejected the write"
            );
            store.0.borrow_mut().limit = usize::MAX;
            if drained {
                scene.owner.drain(DrainStage::Mutations, now);
            }
            if resumed {
                assert!(scene.owner.resume(Resume::Cut));
            }
            let mut acknowledged = Vec::new();
            let mut steps = 0;
            let ended = loop {
                match (scene.owner)
                    .cover_end(reply, &mut acknowledged, now)
                    .unwrap()
                {
                    Cover::Next(next) => {
                        assert!(!drained, "{resumed}: the drained write asks for {next:?}");
                        reply = next.run(&mut client);
                        steps += 1;
                        assert!(steps < 4);
                    }
                    ended => break ended,
                }
            };
            let saturated =
                crate::storage::store_tests::page(&store, page_of(&key(5), record().pages))
                    .saturated;
            scene.turns(4);
            let sent = invalidated(&mut scene);
            if drained {
                assert!(matches!(ended, Cover::Unresolved), "{resumed}: {ended:?}");
                assert_eq!(commits(&store, 5), before, "{resumed}: no saturated write");
                assert!(!saturated, "{resumed}");
                assert!(acknowledged.is_empty() && sent.is_empty(), "{resumed}");
            } else {
                assert!(saturated, "the undrained twin saturates");
                assert_eq!(acknowledged, [(key(5), versions(3, 5))]);
                assert_eq!(sent, [held.request]);
            }
        });
    }
}

/// A drain straight from open to stage 2 ends a ready upload with one `OwnerUnavailable` PUT ERROR, and a later
/// request for stage 1, with no resume between, keeps stage 2 and its INVALIDATE refusal.
#[test]
fn a_drain_to_stage_two_from_open_ends_uploads_and_a_lower_stage_changes_nothing() {
    scene(&PRINCIPALS, |mut scene| {
        let pending = vec![0; 2 * super::geometry::FRAGMENT_LEN as usize];
        let _ = ready_upload(&mut scene, &pending);
        scene.owner.drain(DrainStage::Mutations, scene.turn * 100);
        scene.turns(4);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::OwnerUnavailable]);
        assert_eq!(scene.owner.put_occupancy().live, 0);
        scene.owner.drain(DrainStage::Fills, scene.turn * 100);
        assert_eq!(scene.owner.draining(), Some(DrainStage::Mutations));
        let _ = fenced(&mut scene);
        let mut budget = WorkBudget::new(1 << 12);
        let refused = (scene.owner).invalidate_interval(&key(1), versions(3, 5), 4, &mut budget);
        assert_eq!(refused.err(), Some(InvalidateError::Closed));
        assert!(scene.visible(1));
    });
}

/// A local fill whose writes finished is refused `Closed` at publication in either stage and stays invisible, and
/// a fresh fill after a resume publishes. A RAM invalidation of a resident key removes it in stage 1 and is refused
/// `Closed` with the key kept in stage 2.
#[test]
fn the_local_paths_follow_the_drain_stages() {
    use crate::storage::FillPublishError;
    fn ready_fill<'s, 'a>(
        scene: &mut Scene<'s, 'a>,
        name: u8,
    ) -> crate::storage::WritableFill<'s, 'a, crate::storage::owner_fixture::TestPlatform> {
        let body = payload(100, 6);
        let mut fill = crate::storage::owner_fixture::reserve_at(
            scene.storage,
            &key(name),
            crate::storage::CacheVersion(4),
            0,
            body.len(),
        )
        .unwrap();
        let mut taken = 0;
        while !scene.owner.fill_progress(&fill).is_ready() {
            if taken < body.len() {
                let mut budget = WorkBudget::with_io(0, usize::MAX, usize::MAX);
                taken += scene
                    .owner
                    .receive_fill(&mut fill, &body[taken..], &mut budget)
                    .unwrap_or(0);
            }
            scene.turns(1);
            assert!(scene.turn < 10_000, "the fill finished its writes");
        }
        fill
    }
    for stage in [DrainStage::Fills, DrainStage::Mutations] {
        scene(&PRINCIPALS, |mut scene| {
            let fill = ready_fill(&mut scene, 5);
            scene.owner.drain(stage, scene.turn * 100);
            let published =
                (scene.owner).publish_fill(fill, u64::MAX, 2, &mut WorkBudget::new(1024));
            assert_eq!(published.err(), Some(FillPublishError::Closed), "{stage:?}");
            assert!(!scene.visible(5), "{stage:?}");
            let removed = (scene.owner).invalidate(&key(1), 4, &mut WorkBudget::new(1 << 12));
            match stage {
                DrainStage::Fills => {
                    assert!(removed.is_ok(), "{removed:?}");
                    assert!(!scene.visible(1));
                }
                DrainStage::Mutations => {
                    assert_eq!(removed.err(), Some(InvalidateError::Closed));
                    assert!(scene.visible(1));
                }
            }
            assert!(scene.owner.resume(Resume::Cut));
            let fresh = ready_fill(&mut scene, 6);
            let published =
                (scene.owner).publish_fill(fresh, u64::MAX, 2, &mut WorkBudget::new(1024));
            drop(published.unwrap());
            assert!(
                scene.visible(6),
                "{stage:?}: a fresh fill publishes after the resume"
            );
        });
    }
}

/// In stage 2 headroom pressure evicts no member over many polls; after the resume the same pressure evicts the
/// scene's one published object.
#[test]
fn stage_two_holds_maintenance_removals_until_the_resume() {
    let storage = super::put_tests::fragmentable_storage();
    run_wait_scene(storage, super::owner_tests::OWNER, |mut scene| {
        scene.owner.drain(DrainStage::Mutations, scene.turn * 100);
        let pins = pin_holes(scene.storage, 8);
        scene.polls(100);
        assert_eq!(scene.storage.maintain_totals().evicted, 0);
        assert!(scene.visible(1), "the member stays");
        assert!(scene.owner.resume(Resume::Cut));
        let evicted = (0..100).any(|_| {
            scene.polls(1);
            scene.storage.maintain_totals().evicted == 1
        });
        assert!(evicted, "the resumed owner evicts under the same pressure");
        drop(pins);
    });
}

/// A volume lost to a refused local write, while draining or before the drain, latches into admission at the next
/// drain or resume with no GET, PUT or INVALIDATE between. A drain after the loss installs no stage and records no
/// `draining`; `resume` returns false and keeps the exit's status, `draining` for a loss during a drain and `received`
/// for a loss before it; a later drain installs no stage, and a BEGIN and an INVALIDATE stay refused.
#[test]
fn a_lost_volume_ends_the_drain_and_refuses_the_resume() {
    for first in [Some(DrainStage::Fills), Some(DrainStage::Mutations), None] {
        viewed_scene(|mut scene| {
            scene.owner.exit_received(operation());
            if let Some(stage) = first {
                scene.owner.drain(stage, 0);
            }
            let body = payload(100, 6);
            let mut fill = crate::storage::owner_fixture::reserve_at(
                scene.storage,
                &key(5),
                crate::storage::CacheVersion(4),
                0,
                body.len(),
            )
            .unwrap();
            scene.control.set_gone();
            let mut budget = WorkBudget::with_io(0, usize::MAX, usize::MAX);
            let _ = scene.owner.receive_fill(&mut fill, &body, &mut budget);
            scene.turns(4);
            assert!(
                scene.owner.lost(),
                "{first:?}: a refused local write lost the volume"
            );
            drop(fill);
            let status = match first {
                Some(_) => ExitStatus::Draining,
                None => {
                    scene.owner.drain(DrainStage::Fills, 0);
                    assert_eq!(scene.owner.draining(), None, "the drain latched the loss");
                    ExitStatus::Received
                }
            };
            assert_eq!(exit(&scene), Some((operation(), status)), "{first:?}");
            assert!(!scene.owner.resume(Resume::Cut), "{first:?}");
            assert_eq!(scene.owner.draining(), None, "{first:?}");
            assert_eq!(exit(&scene), Some((operation(), status)), "{first:?}");
            scene.owner.drain(DrainStage::Mutations, 0);
            assert_eq!(scene.owner.draining(), None, "{first:?}");
            assert_eq!(
                begin_status(&mut scene, 1, 5),
                Some(Status::OwnerUnavailable)
            );
            let mut budget = WorkBudget::new(1 << 12);
            let refused =
                (scene.owner).invalidate_interval(&key(5), versions(3, 5), 4, &mut budget);
            assert_eq!(refused.err(), Some(InvalidateError::Closed), "{first:?}");
        });
    }
}

fn operation() -> ExitOperation {
    ExitOperation::new([7; 16]).unwrap()
}

/// The owner's exit operation and status in its report entry at the scene's time.
fn exit(scene: &Scene<'_, '_>) -> Option<(ExitOperation, ExitStatus)> {
    let entry = entry(scene, scene.turn * 100, &Observed::UNAVAILABLE);
    entry.exit.map(|exit| (exit.operation, exit.status))
}

/// A scene whose owner serves generation 3 with a shard view naming its volume, both clients holding sessions.
fn viewed_scene(body: impl FnOnce(Scene<'_, '_>)) {
    scene(&PRINCIPALS, |mut scene| {
        viewed(&mut scene, active());
        scene.reopen(1);
        body(scene);
    });
}

/// From either stage, `resume` reopens PUT BEGIN with every session kept and the tenure unchanged, and the entry
/// reads `resumed` with the reason given.
#[test]
fn resume_reopens_a_begin_from_either_stage_with_no_session_ended() {
    for (stage, reason) in [
        (DrainStage::Fills, Resume::Cut),
        (DrainStage::Mutations, Resume::Store),
    ] {
        viewed_scene(|mut scene| {
            scene.owner.exit_received(operation());
            scene.owner.drain(DrainStage::Fills, 0);
            scene.owner.drain(stage, 0);
            assert_eq!(scene.owner.draining(), Some(stage));
            let refused = begin_status(&mut scene, 1, 5);
            assert_eq!(refused, Some(Status::OwnerUnavailable));
            let epochs: Vec<_> = (0..2)
                .map(|peer| scene.owner.session_epoch(PeerId(peer)))
                .collect();
            let tenure = scene.owner.tenure().target();
            assert!(scene.owner.resume(reason), "{stage:?}");
            assert_eq!(scene.owner.draining(), None);
            assert_eq!(
                exit(&scene),
                Some((operation(), ExitStatus::Resumed(reason)))
            );
            let _ = scene.begin(1, request(2, 1), 6);
            let after: Vec<_> = (0..2)
                .map(|peer| scene.owner.session_epoch(PeerId(peer)))
                .collect();
            assert!(epochs.iter().all(Option::is_some), "{stage:?}");
            assert_eq!(after, epochs, "{stage:?}: no session ended");
            assert_eq!(scene.owner.tenure().target(), tenure, "{stage:?}");
        });
    }
}

/// After a planned withdrawal `resume` returns false, keeps the stage and the exit, which reads `withdrawn` at once;
/// after the close every session has ended, `resume` returns false and the exit is unchanged.
#[test]
fn resume_after_the_withdrawal_and_the_close_changes_nothing() {
    viewed_scene(|mut scene| {
        scene.owner.exit_received(operation());
        scene.owner.drain(DrainStage::Mutations, 0);
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Draining)));
        let withdraw = Event::Withdraw(Cause::Planned);
        scene.owner.authority_event(withdraw, scene.turn * 100);
        let withdrawn = Some((operation(), ExitStatus::Withdrawn));
        assert_eq!(exit(&scene), withdrawn, "no shard view between");
        assert!(!scene.owner.resume(Resume::Deadline), "a withdrawn tenure");
        assert_eq!(scene.owner.draining(), Some(DrainStage::Mutations));
        assert_eq!(exit(&scene), withdrawn);
        scene.owner.close(0);
        assert!(!scene.owner.resume(Resume::Deadline), "a closed owner");
        assert_eq!(scene.owner.draining(), None);
        assert_eq!(exit(&scene), withdrawn);
        let ended = (0..2).all(|peer| scene.owner.session_epoch(PeerId(peer)).is_none());
        assert!(ended, "every session ended");
    });
}

/// A closed owner stays closed through a drain and a refused resume.
#[test]
fn resume_and_drain_leave_a_closed_owner_closed() {
    scene(&PRINCIPALS, |mut scene| {
        scene.owner.close(0);
        let closed =
            |scene: &Scene<'_, '_>| scene.owner.blockers().is_none_or(|blockers| !blockers.open);
        scene.owner.drain(DrainStage::Fills, 0);
        assert_eq!(scene.owner.draining(), None);
        assert!(closed(&scene), "the drain left the owner closed");
        assert!(!scene.owner.resume(Resume::Store));
        assert_eq!(scene.owner.draining(), None);
        assert!(closed(&scene), "the resume left the owner closed");
    });
}

/// The entry's exit is absent with no planned operation, reads `received`, then `draining` in both stages, then
/// `resumed` with the reason given, each with the operation identity, and the entry encodes and decodes to itself.
#[test]
fn the_entry_reads_draining_during_a_drain_and_resumed_after_a_resume() {
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        assert_eq!(exit(&scene), None, "no planned operation");
        scene.owner.exit_received(operation());
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Received)));
        scene.owner.drain(DrainStage::Fills, now);
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Draining)));
        scene.owner.drain(DrainStage::Mutations, now);
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Draining)));
        assert!(scene.owner.resume(Resume::Standby));
        let resumed = ExitStatus::Resumed(Resume::Standby);
        assert_eq!(exit(&scene), Some((operation(), resumed)));
    });
}

/// The owner feeds each shard view to its tracker. A later view keeps a serving owner's draining exit, which then
/// resumes `resumed-deadline`, and keeps a received exit, which a resume of the open owner records as
/// `resumed-deadline`. A resume before any drain records its reason, which a later view keeps. A successor view
/// that withdraws the tenure exits a draining exit in the same call.
#[test]
fn shard_views_move_the_owner_s_exit() {
    for drained in [true, false] {
        scene(&[], |mut scene| {
            let now = viewed(&mut scene, active());
            let own = shard_at(token(&scene), 3, token(&scene).epoch.get() / 2);
            scene.owner.exit_received(operation());
            if drained {
                scene.owner.drain(DrainStage::Fills, now);
            }
            scene.turn += 100;
            let exhid = token(&scene).exhid;
            observe(&mut scene, Some(own), Some(active()), exhid);
            let pending = if drained {
                ExitStatus::Draining
            } else {
                ExitStatus::Received
            };
            assert_eq!(exit(&scene), Some((operation(), pending)));
            assert_eq!(scene.owner.resume(Resume::Deadline), drained);
            let resumed = Some((operation(), ExitStatus::Resumed(Resume::Deadline)));
            assert_eq!(exit(&scene), resumed, "{drained}");
        });
    }
    scene(&[], |mut scene| {
        viewed(&mut scene, active());
        let own = shard_at(token(&scene), 3, token(&scene).epoch.get() / 2);
        scene.owner.exit_received(operation());
        assert!(!scene.owner.resume(Resume::Standby), "admission was open");
        scene.turn += 100;
        let exhid = token(&scene).exhid;
        observe(&mut scene, Some(own), Some(active()), exhid);
        let resumed = Some((operation(), ExitStatus::Resumed(Resume::Standby)));
        assert_eq!(exit(&scene), resumed);
    });
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        let successor = shard_at(token(&scene), 4, 1);
        scene.owner.exit_received(operation());
        scene.owner.drain(DrainStage::Mutations, now);
        scene.turn += 100;
        let exhid = token(&scene).exhid;
        observe(&mut scene, Some(successor), Some(active()), exhid);
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Exited)));
    });
}

/// A withdrawn exit waits for its successor: an own-tenure view long after the receipt reads `waiting`, a repeat of
/// the operation keeps it, and a successor view then reads `exited`.
#[test]
fn a_withdrawn_exit_waits_for_its_successor_however_late() {
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        let own = shard_at(token(&scene), 3, token(&scene).epoch.get() / 2);
        let successor = shard_at(token(&scene), 4, 1);
        let exhid = token(&scene).exhid;
        scene.owner.exit_received(operation());
        scene.owner.drain(DrainStage::Mutations, now);
        let withdraw = Event::Withdraw(Cause::Planned);
        scene.owner.authority_event(withdraw, scene.turn * 100);
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Withdrawn)));
        scene.turn = now / 100 + 1_000;
        observe(&mut scene, Some(own), Some(active()), exhid);
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Waiting)));
        scene.owner.exit_received(operation());
        observe(&mut scene, Some(own), Some(active()), exhid);
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Waiting)));
        observe(&mut scene, Some(successor), Some(active()), exhid);
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Exited)));
    });
}

/// A drain request at the stage the owner already holds records `draining` on an operation that replaced the tracked
/// one during the drain, in either stage, and keeps the stage.
#[test]
fn a_drain_at_the_held_stage_records_draining_on_a_replacement_operation() {
    for stage in [DrainStage::Fills, DrainStage::Mutations] {
        scene(&[], |mut scene| {
            let now = viewed(&mut scene, active());
            let second = ExitOperation::new([8; 16]).unwrap();
            scene.owner.exit_received(operation());
            scene.owner.drain(stage, now);
            scene.owner.exit_received(second);
            assert_eq!(exit(&scene), Some((second, ExitStatus::Received)));
            scene.owner.drain(stage, now);
            assert_eq!(scene.owner.draining(), Some(stage));
            assert_eq!(exit(&scene), Some((second, ExitStatus::Draining)));
        });
    }
}

/// Another operation replaces the tracked exit and reads `received`. A repeat of it keeps its status: `draining`
/// after the drain's next stage, `withdrawn` after a planned withdrawal, and `waiting` at its receipt tenure.
#[test]
fn another_operation_replaces_the_tracked_exit_and_a_repeat_keeps_it() {
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        let own = shard_at(token(&scene), 3, token(&scene).epoch.get() / 2);
        let exhid = token(&scene).exhid;
        let second = ExitOperation::new([8; 16]).unwrap();
        scene.owner.exit_received(operation());
        scene.owner.drain(DrainStage::Fills, now);
        assert_eq!(exit(&scene), Some((operation(), ExitStatus::Draining)));
        scene.owner.exit_received(second);
        assert_eq!(exit(&scene), Some((second, ExitStatus::Received)));
        scene.owner.drain(DrainStage::Mutations, now);
        for status in [
            ExitStatus::Draining,
            ExitStatus::Withdrawn,
            ExitStatus::Waiting,
        ] {
            match status {
                ExitStatus::Withdrawn => {
                    let withdraw = Event::Withdraw(Cause::Planned);
                    scene.owner.authority_event(withdraw, scene.turn * 100);
                }
                ExitStatus::Waiting => observe(&mut scene, Some(own), Some(active()), exhid),
                _ => {}
            }
            scene.owner.exit_received(second);
            assert_eq!(exit(&scene), Some((second, status)));
        }
    });
}

/// `transfer_submitted` records one transfer from no handoff: it refuses on a serving tenure and on a tenure
/// withdrawn for the planned exit whose admission still drains, records the first submission after the owner closed,
/// and refuses a second submission, which leaves the recorded target.
#[test]
fn transfer_submitted_records_one_transfer_and_keeps_its_target() {
    use crate::failover::takeover::tests::{b_host, c_host};
    use crate::net::Handoff;
    viewed_scene(|mut scene| {
        assert!(
            !scene.owner.transfer_submitted(c_host()),
            "a serving tenure"
        );
        assert_eq!(scene.owner.transfer(), None);
        scene.owner.drain(DrainStage::Mutations, 0);
        let withdraw = Event::Withdraw(Cause::Planned);
        scene.owner.authority_event(withdraw, scene.turn * 100);
        assert!(
            !scene.owner.transfer_submitted(c_host()),
            "a withdrawn tenure whose admission drains"
        );
        assert_eq!(scene.owner.transfer(), None);
        let _ = scene.owner.close(scene.turn * 100);
        assert!(scene.owner.transfer_submitted(c_host()));
        let outstanding = Some(Handoff::Outstanding { target: c_host() });
        assert_eq!(scene.owner.transfer(), outstanding);
        assert!(
            !scene.owner.transfer_submitted(b_host()),
            "a second submission"
        );
        assert_eq!(
            scene.owner.transfer(),
            outstanding,
            "the first target stays"
        );
    });
}

/// A store holding the scene tenure's shard record at `attempts` with `standby` named and a checkpoint, and the
/// read of it.
fn handoff_store(
    session: &crate::storage::Session,
    attempts: u32,
    standby: crate::failover::records::Host,
) -> crate::storage::store::sim::Shared {
    let own = session.target();
    let generation = own.generation.get();
    let record = crate::failover::records::ShardRecord {
        shard: session.shard(),
        owner: own.owner,
        standby: Some(standby),
        checkpoint: Some(crate::failover::records::NamedCheckpoint {
            slot: 1,
            session: crate::net::ownership::session_of(generation as u32, 2),
            capture: 2,
            units: 3,
        }),
        generation: own.generation,
        attempts,
        ..crate::storage::store_tests::record()
    };
    let store = crate::storage::store::sim::Shared::new();
    crate::storage::store_tests::client(&store)
        .create_shard(record)
        .expect("the handoff record is created");
    store
}

/// The acknowledged transfer of `store`'s record to `target` under `session`.
fn receipt(
    store: &crate::storage::store::sim::Shared,
    session: &crate::storage::Session,
    target: crate::failover::records::Host,
) -> crate::storage::store::Transferred {
    use crate::storage::store::{Key, Outgoing};
    let mut client = crate::storage::store_tests::client(store);
    let read = client
        .read::<crate::failover::records::ShardRecord>(Key::Shard(session.shard()))
        .unwrap();
    let gate = crate::failover::reconcile::StandbyGate::qualified();
    client
        .transfer(&gate, &read, &Outgoing::of(session), target)
        .expect("the transfer commits")
}

/// `transfer_committed` settles the outstanding transfer only on the receipt of this tenure's transfer to the
/// recorded target: with no transfer outstanding, on a receipt that names another target, and on a receipt of the
/// same host's next tenure, which names the target at a later `E`, it returns false, leaves the handoff as it was
/// and `serve::ended` names no exit. The tenure's own receipt settles it, and `serve::ended` then ends `Stopped`.
#[test]
fn transfer_committed_settles_only_the_receipt_of_this_tenure_s_transfer_to_its_target() {
    use crate::failover::takeover::tests::{b_host, c_host};
    use crate::host::Exit;
    use crate::net::Handoff;
    use crate::storage::Session;
    use crate::storage::store::Key;
    viewed_scene(|mut scene| {
        let own = scene.owner.tenure().target();
        let volume = active().volume;
        let now = scene.turn * 100;
        // This tenure's transfer to C, its transfer to B, and the transfer of the host's next tenure to C.
        let to_c = handoff_store(scene.owner.tenure(), own.attempts, c_host());
        let named = receipt(&to_c, scene.owner.tenure(), c_host());
        let to_b = handoff_store(scene.owner.tenure(), own.attempts, b_host());
        let other_target = receipt(&to_b, scene.owner.tenure(), b_host());
        let later = handoff_store(scene.owner.tenure(), own.attempts, c_host());
        let mut client = crate::storage::store_tests::client(&later);
        let read = client
            .read::<crate::failover::records::ShardRecord>(Key::Shard(scene.owner.tenure().shard()))
            .unwrap();
        let next = Session::activate(client.bump(&read).unwrap()).unwrap();
        let other_attempt = receipt(&later, &next, c_host());
        assert_eq!(
            other_attempt.committed().value().attempts,
            own.attempts + 2,
            "premise: the next tenure's receipt names a later E"
        );

        assert!(
            !scene.owner.transfer_committed(&named, volume, now),
            "no transfer is outstanding"
        );
        assert_eq!(scene.owner.transfer(), None);
        scene.owner.drain(DrainStage::Mutations, 0);
        scene
            .owner
            .authority_event(Event::Withdraw(Cause::Planned), now);
        let _ = scene.owner.close(now);
        assert!(scene.owner.transfer_submitted(c_host()));
        let outstanding = Some(Handoff::Outstanding { target: c_host() });
        for (refused, case) in [
            (&other_target, "another target"),
            (&other_attempt, "another attempt"),
        ] {
            assert!(
                !scene.owner.transfer_committed(refused, volume, now),
                "{case}"
            );
            assert_eq!(scene.owner.transfer(), outstanding, "{case}");
            assert_eq!(crate::host::serve::ended(&scene.owner), None, "{case}");
        }
        assert!(scene.owner.transfer_committed(&named, volume, now));
        assert_eq!(scene.owner.transfer(), Some(Handoff::Committed));
        assert_eq!(crate::host::serve::ended(&scene.owner), Some(Exit::Stopped));
    });
}
