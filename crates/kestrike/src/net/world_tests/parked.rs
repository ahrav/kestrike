//! Parked GETs under the turn controller: the GET client reads the upload's
//! key while the upload is open, so its GET joins the fill and parks, and
//! the profiles add each fault a parked GET meets: a duplicate from the
//! client's own retries, a cancel, the follower's own deadline, the
//! producer's cancel, a session change and a saturated follower cap. Every
//! owner poll asserts the turn limits and the parked GETs' place in the
//! request census ([`Mixed::check_turn_limits`](super::Mixed)); each run
//! records the parked high-water mark and ends with none parked.

use crate::sim::action::{ActionKind, Profile};
use crate::sim::turn::End;

use super::super::audit::Verdict;
use super::super::fetch::Outcome;
use super::super::frame::Status;
use super::super::owner_tests::OWNER;
use super::super::parked::{FollowConfig, PLANT, Plant};
use super::{Mixed, Plan, Ran, UPLOAD, UPLOAD_PLAN, exactly_read, mixed};

/// The GET client's read of the upload's key, proposed once the supplier
/// deferred, so the GET finds the upload open.
pub(super) const PARKED_PLAN: Plan = Plan {
    read_after_publish: false,
    read_during_stall: true,
    read_resident: false,
    withhold: 3,
    // The turns after the goal let the owner detach a follower whose
    // request ended last, so the parked GETs drain before the run ends.
    drain: 400,
    ..UPLOAD_PLAN
};

/// Every planned GET decided.
fn decided(world: &Mixed<'_, '_, '_>) -> bool {
    world.plan.gets == [0, 0] && world.gets.iter().flatten().all(|get| get.outcome.is_some())
}

/// The owner's most GETs parked at once, after asserting it ended with none
/// parked and its own counters agree.
fn drained(ran: &Ran, name: &str) -> u32 {
    let high = ran.seen.iter().map(|seen| seen.parked).max().unwrap_or(0);
    assert_eq!(
        ran.seen.last().map(|seen| seen.parked),
        Some(0),
        "{name}: the parked GETs drained"
    );
    // A GET can park and detach within one owner poll, which no turn's
    // sample sees, so the owner's mark bounds the sampled one.
    assert!(high <= ran.parked.high_water, "{name}: the owner's mark");
    assert_eq!(
        ran.parked.joined,
        ran.parked.woke + ran.parked.ended + ran.parked.detached,
        "{name}: every join woke, ended or detached"
    );
    ran.parked.high_water
}

/// A clean run: the controller ended `Done` and the audit passed.
fn passed(ran: &Ran, name: &str) {
    assert_eq!(ran.report.end, End::Done, "{name}");
    assert_eq!(ran.audit, Verdict::Pass, "{name}");
}

/// A parked GET follows the deferring upload and reads the version it
/// published exactly, at each root.
#[test]
fn a_parked_get_follows_a_deferring_upload_and_reads_it_exactly() {
    let mut parked = 0;
    for root in 1..=4 {
        let profile = Profile {
            name: "parked GET behind a deferring upload",
            declared: [UPLOAD.as_slice(), &[ActionKind::DeferSupply]].concat(),
            root,
        };
        let ran = mixed(&profile, PARKED_PLAN, exactly_read);
        let name = format!("root {root}");
        passed(&ran, &name);
        parked = parked.max(drained(&ran, &name));
        assert!(ran.parked.woke >= 1, "{name}: {:?}", ran.parked);
    }
    assert!(parked >= 1, "some run parked its GET");
}

/// Each parked-GET fault is reached in some run of its profile, every run
/// passes with the turn limits and the census asserted at every owner poll,
/// and each run ends with none parked:
///
/// - a duplicate: the GET client's retries resend the GET while it is
///   parked;
/// - a cancel of a parked GET, which detaches its follower;
/// - the follower's own deadline, which detaches it before any producer
///   terminal;
/// - the producer's cancel, which ends its follower `Missing`;
/// - a session change of the GET client;
/// - a saturated total cap: the uploading client's GET of its own key
///   parks first, so the other client's is refused `RequestPressure`.
#[test]
fn parked_gets_meet_every_fault_under_the_turn_controller() {
    let deferring = [UPLOAD.as_slice(), &[ActionKind::DeferSupply]].concat();
    let with = |kinds: &[ActionKind]| [deferring.as_slice(), kinds].concat();
    let stalled = Plan {
        withhold: u32::MAX,
        ..PARKED_PLAN
    };
    let cases: [(&str, Vec<ActionKind>, Plan); 5] = [
        ("cancel", with(&[ActionKind::Cancel]), stalled),
        ("follower deadline", deferring.clone(), stalled),
        (
            "producer cancel",
            with(&[ActionKind::PutCancel]),
            Plan {
                while_parked: true,
                ..stalled
            },
        ),
        (
            "session change",
            with(&[ActionKind::SessionChange]),
            Plan {
                sessions: 1,
                while_parked: true,
                ..stalled
            },
        ),
        (
            "saturated cap",
            deferring.clone(),
            Plan {
                gets: [1, 1],
                get_during_upload: true,
                upload_reads: true,
                follow: Some(FollowConfig {
                    followers: 1,
                    ..OWNER.follow
                }),
                ..stalled
            },
        ),
    ];
    let mut reached = [false; 6];
    for (name, declared, plan) in cases {
        for root in 1..=4 {
            let profile = Profile {
                name: "parked GET faults",
                declared: declared.clone(),
                root,
            };
            let ran = mixed(&profile, plan, decided);
            let at = format!("{name} at root {root}");
            passed(&ran, &at);
            let high = drained(&ran, &at);
            let outcomes: Vec<Outcome> = ran.decided.iter().map(|got| got.outcome).collect();
            // A duplicate the owner took on a turn that began with a GET parked.
            reached[0] |= ran
                .seen
                .windows(2)
                .any(|pair| pair[0].parked > 0 && pair[1].duplicates > pair[0].duplicates);
            match name {
                "cancel" => {
                    reached[1] |= ran.parked.detached >= 1
                        && outcomes.contains(&Outcome::Failed(Status::Cancelled));
                }
                "follower deadline" => {
                    // The follower's own deadline ended its request, which
                    // detached it, before any producer terminal ended it.
                    reached[2] |= ran.parked.detached >= 1
                        && ran.parked.ended == 0
                        && outcomes.contains(&Outcome::Failed(Status::TimedOut));
                }
                "producer cancel" => {
                    reached[3] |= ran.parked.ended >= 1 && outcomes.contains(&Outcome::Missing);
                }
                "session change" => {
                    reached[4] |= high >= 1
                        && ran.acts.iter().any(|act| {
                            act.kind == ActionKind::SessionChange
                                && super::witnessed(act.kind, act.outcome)
                        });
                }
                _ => {
                    reached[5] |= ran.parked.total_saturated >= 1
                        && outcomes.contains(&Outcome::Pressure(Status::RequestPressure));
                }
            }
        }
    }
    assert_eq!(
        reached, [true; 6],
        "duplicate, cancel, deadline, producer, session, cap"
    );
}

/// [`Plant::ReleaseParked`] planted on this thread until the value drops.
struct Planted;

impl Planted {
    fn release_parked() -> Self {
        PLANT.with(|plant| plant.set(Plant::ReleaseParked));
        Self
    }
}

impl Drop for Planted {
    fn drop(&mut self) {
        PLANT.with(|plant| plant.set(Plant::None));
    }
}

/// An owner that releases an ended request's slot while its follower stays
/// parked leaves the parked table naming a request the namespace no longer
/// holds. The cancel profile of
/// [`parked_gets_meet_every_fault_under_the_turn_controller`] under that
/// owner fails the census check the world asserts at every owner poll.
#[test]
#[should_panic(expected = "the parked GETs left the request census")]
fn negative_control_a_parked_slot_released_before_its_detach_fails_the_turn_census() {
    let _planted = Planted::release_parked();
    let declared = [
        UPLOAD.as_slice(),
        &[ActionKind::DeferSupply, ActionKind::Cancel],
    ]
    .concat();
    let stalled = Plan {
        withhold: u32::MAX,
        ..PARKED_PLAN
    };
    for root in 1..=4 {
        let profile = Profile {
            name: "parked GET faults",
            declared: declared.clone(),
            root,
        };
        let ran = mixed(&profile, stalled, decided);
        let at = format!("cancel at root {root}");
        passed(&ran, &at);
        drained(&ran, &at);
    }
}
