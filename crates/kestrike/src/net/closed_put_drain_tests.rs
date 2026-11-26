//! Close keeps a writing fill until its writes end, rekey refuses `Busy`,
//! and `blockers()` clears after the drain.
//!
//! Both tests run one upload of two fragments at the owner, with a follower joined to its fill through
//! `Storage::join_fill`, and record what the owner reports at each step. The scene and its follower end before
//! a test asserts on what it recorded.
//!
//! - `a_closed_put_stays_draining_until_the_device_ends_its_writes`: the DATA is accepted and the owner polls
//!   while the device does not tick, so the upload's write commands are outstanding. Before the close the
//!   census reads one active request and a re-key is refused `Busy` with that census. `Owner::close` runs and
//!   the owner polls five more times: after every poll the census reads the PUT as one draining request,
//!   `blockers()` reports that census on a closed owner, the re-key is refused `Busy` with it, and the follower
//!   still observes the fill pending. The device then ticks: the request leaves the census only after the
//!   device completed writes, the follower observes `Failed(Closed)`, and `blockers()` clears.
//! - `a_closed_put_with_no_write_outstanding_ends_without_the_device`: the control. The same upload is closed
//!   before any DATA arrives, so no write command is outstanding, and the same polls without a device tick end
//!   it: the census empties and the follower observes `Failed(Closed)`. The wait of the first test therefore
//!   comes from the outstanding writes, not from the close.

use crate::storage::{FillEnd, FillFailure, ObserveError, Observed, WorkBudget};

use super::geometry::FRAGMENT_LEN;
use super::owner::OwnerRekeyError;
use super::owner_tests::{PRINCIPALS, entries, key, payload};
use super::put_tests::{Scene, ready_upload, scene};
use super::requests::RequestCensus;
use super::session::RekeyError;

/// The polls the owner runs after the close while the device does not tick.
const POLLS: usize = 5;

/// What the owner reports at one step.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Step {
    census: RequestCensus,
    /// The census `blockers()` reports and whether it reports the owner open, or `None` for no blocker.
    blockers: Option<(RequestCensus, bool)>,
    rekey: Result<(), OwnerRekeyError>,
    follower: Result<Observed, ObserveError>,
    /// The volume's write commands submitted and done.
    writes: (u64, u64),
}

/// What one run recorded.
#[derive(Debug)]
struct Run {
    before: Step,
    after_close: Vec<Step>,
    /// The volume's writes done when the census first read empty, within the turns the run allows.
    left_at: Option<u64>,
    ended: Result<Observed, ObserveError>,
    /// Whether `blockers()` still reports one after the follower detached and the device ticked on.
    blocked: bool,
}

fn step(
    scene: &mut Scene<'_, '_>,
    follower: &crate::storage::FillFollower<'_, crate::storage::owner_fixture::TestPlatform>,
) -> Step {
    let report = scene.owner.volume_report();
    Step {
        census: scene.owner.census(),
        blockers: scene
            .owner
            .blockers()
            .map(|blockers| (blockers.census, blockers.open)),
        rekey: scene.owner.rekey(&entries(), 2, scene.turn * 100),
        follower: follower.observe(4, &mut WorkBudget::new(1 << 12)),
        writes: (report.writes_submitted, report.writes_done),
    }
}

/// One upload of two fragments with a follower joined, its DATA sent when `data` is set, then the close, [`POLLS`]
/// owner polls with no device tick and a step recorded after each, then device ticks until the census empties.
fn closed_upload(data: bool, seed: u64) -> Run {
    let mut run = None;
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, seed);
        let (at, serial) = ready_upload(&mut scene, &object);
        let storage = scene.storage;
        let follower = storage
            .join_fill(&key(5), u64::MAX, 4, &mut WorkBudget::new(1 << 12))
            .ok()
            .filter(|follower| follower.serial() == serial);
        let Some(follower) = follower else {
            return;
        };
        if data {
            for index in 0..2 {
                let (header, body) = scene.fragment(at, serial, &object, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
        }
        scene.polls(2);
        let before = step(&mut scene, &follower);
        scene.owner.close(scene.turn * 100);
        let mut after_close = Vec::new();
        for _ in 0..POLLS {
            scene.polls(1);
            after_close.push(step(&mut scene, &follower));
        }
        let mut left_at = None;
        for _ in 0..60 {
            if scene.live() == 0 {
                left_at = Some(scene.owner.volume_report().writes_done);
                break;
            }
            scene.turns(1);
        }
        let ended = follower.observe(4, &mut WorkBudget::new(1 << 12));
        drop(follower);
        scene.turns(40);
        let blocked = scene.owner.blockers().is_some();
        run = Some(Run {
            before,
            after_close,
            left_at,
            ended,
            blocked,
        });
    });
    run.expect("premise: the upload was granted and a follower joined its fill")
}

fn busy(census: RequestCensus) -> Result<(), OwnerRekeyError> {
    Err(OwnerRekeyError::Rekey(RekeyError::Busy { census }))
}

const ACTIVE: RequestCensus = RequestCensus {
    active: 1,
    draining: 0,
    retired: 0,
};
const DRAINING: RequestCensus = RequestCensus {
    active: 0,
    draining: 1,
    retired: 0,
};
const CLOSED: Result<Observed, ObserveError> =
    Ok(Observed::Ended(FillEnd::Failed(FillFailure::Closed)));

#[test]
fn a_closed_put_stays_draining_until_the_device_ends_its_writes() {
    let run = closed_upload(true, 15);
    let (submitted, done) = run.before.writes;
    assert!(
        submitted > done,
        "premise: the upload's writes are outstanding at the close: {run:?}"
    );
    assert_eq!(
        (run.before.census, &run.before.rekey, &run.before.follower),
        (ACTIVE, &busy(ACTIVE), &Ok(Observed::Pending)),
        "premise: before the close the PUT is one active request and a re-key is refused Busy with that census"
    );
    for (poll, step) in run.after_close.iter().enumerate() {
        assert_eq!(
            step.writes,
            (submitted, done),
            "premise: the device completed nothing by poll {poll} after the close"
        );
        assert_eq!(
            step,
            &Step {
                census: DRAINING,
                blockers: Some((DRAINING, false)),
                rekey: busy(DRAINING),
                follower: Ok(Observed::Pending),
                writes: (submitted, done),
            },
            "at poll {poll} after the close the writing PUT is one draining request, blockers() and \
             the re-key report it, and its fill has not ended"
        );
    }
    assert_eq!(run.after_close.len(), POLLS);
    assert!(
        run.left_at.is_some_and(|at| at > done),
        "the request leaves the census only after the device completed writes: {run:?}"
    );
    assert_eq!(
        run.ended, CLOSED,
        "the drained fill ended with the close's failure"
    );
    assert!(!run.blocked, "blockers() clears after the drain");
}

#[test]
fn a_closed_put_with_no_write_outstanding_ends_without_the_device() {
    let run = closed_upload(false, 16);
    let (submitted, done) = run.before.writes;
    assert_eq!(
        submitted, done,
        "premise: no write is outstanding at the close: {run:?}"
    );
    assert_eq!(
        (run.before.census, &run.before.rekey, &run.before.follower),
        (ACTIVE, &busy(ACTIVE), &Ok(Observed::Pending)),
        "premise: before the close the PUT is one active request"
    );
    let last = run.after_close.last().expect("the polls after the close");
    assert_eq!(
        (last.census, &last.follower, last.writes),
        (RequestCensus::default(), &CLOSED, (submitted, done)),
        "a closed PUT with no write outstanding ends within the polls, with no device tick: {run:?}"
    );
    assert_eq!(run.ended, CLOSED);
    assert!(!run.blocked, "blockers() clears after the drain");
}
