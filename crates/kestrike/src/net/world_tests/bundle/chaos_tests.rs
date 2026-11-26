//! The `contended` profile and its control at the bundle seam: pinned
//! passing roots reach every chaos point and fire the points a pass can
//! fire, a refused root fires each other point alone, an unarmed profile
//! run after an armed one records its own bundle, and `contended-acked`
//! fails through the rule for an upload collected as published without its
//! result.

use crate::oracle::Obligation;
use crate::sim::chaos::{Census, Point, census};
use crate::sim::trace::{Loaded, Outcome, Terminal};
use crate::sim::turn::End;

use super::super::super::frame::Status;
use super::super::super::observe::Failure;
use super::super::super::upload::UploadOutcome;
use super::super::replay::{FailureIdentity, premise, violated};
use super::super::{Mixed, Plan, Plant};
use super::tests::{manifest, ran, rerun, rerun_until};
use super::{Site, named};

/// Roots of `contended` whose census fires `gate-busy` and `capture-busy`
/// and whose runs pass.
const PINNED: [u64; 3] = [18, 21, 28];

/// Roots of `contended` whose upload a fired point refused `Contended`.
const REFUSED: [u64; 3] = [2, 3, LOST];

/// A root of `contended` whose one fired point is `exchange-lost`: a fire
/// of it refuses the run's one upload, so it fires in no passing run.
const LOST: u64 = 71;

/// The points a passing `contended` run can fire.
pub(crate) const FIRED_IN_A_PASS: [Point; 2] = [Point::GateBusy, Point::CaptureBusy];

/// The points no passing `contended` run fires, because each fire of one
/// refuses the run's one upload, each with a root of [`REFUSED`] on which
/// it is the one point that fires.
const FIRED_ALONE: [(Point, u64); 1] = [(Point::ExchangeLost, LOST)];

pub(crate) const PUBLISHED: u64 = PINNED[0];

fn rooted(profile: &str, root: u64) -> (Terminal, [u8; 32], Loaded) {
    let mut manifest = manifest(profile, 1);
    manifest.root = root;
    ran(&manifest)
}

fn counted(loaded: &Loaded) -> [Census; Point::ALL.len()] {
    census(&loaded.tape).expect("a recorded tape")
}

/// Fails, by the point's name, unless `point` fires on `loaded`'s tape
/// and no other point does.
fn fires_alone(loaded: &Loaded, point: Point, root: u64) {
    for (other, counts) in Point::ALL.iter().zip(counted(loaded)) {
        assert_eq!(
            counts.fired > 0,
            *other == point,
            "root {root}: {} fires {} where {} fires alone",
            other.row().name,
            counts.fired,
            point.row().name
        );
    }
}

/// Every point is in [`FIRED_IN_A_PASS`] or in [`FIRED_ALONE`], and in one
/// of them only. Over the pinned roots, each a pass, every point is reached
/// and the points a pass can fire fire; each point of [`FIRED_ALONE`]
/// fires alone on its root. So no point is silent in the profile that arms
/// it, and the failure names the point, as when its call site is gone.
#[test]
fn every_armed_point_is_reached_and_fires_in_the_pinned_roots() {
    for point in Point::ALL {
        let alone = FIRED_ALONE.iter().filter(|(other, _)| *other == point);
        assert_eq!(
            usize::from(FIRED_IN_A_PASS.contains(&point)) + alone.count(),
            1,
            "{} stands in other than one row of FIRED_IN_A_PASS and FIRED_ALONE",
            point.row().name
        );
    }
    for (point, root) in FIRED_ALONE {
        assert!(
            REFUSED.contains(&root),
            "{}'s root {root} is missing from REFUSED, whose checks judge its refusal",
            point.row().name
        );
    }
    let mut total = [Census::default(); Point::ALL.len()];
    for root in PINNED {
        let (terminal, _, loaded) = rooted("contended", root);
        assert!(terminal.counts(), "root {root}: {terminal:?}");
        for (sum, point) in total.iter_mut().zip(counted(&loaded)) {
            sum.reached += point.reached;
            sum.fired += point.fired;
        }
    }
    for (point, counts) in Point::ALL.iter().zip(total) {
        let name = point.row().name;
        assert!(counts.reached > 0, "{name} is never reached in {PINNED:?}");
        let fires = FIRED_IN_A_PASS.contains(point);
        assert_eq!(
            counts.fired > 0,
            fires,
            "{name} fires {} in {PINNED:?}",
            counts.fired
        );
    }
    for (point, root) in FIRED_ALONE {
        let (_, _, alone) = rooted("contended", root);
        fires_alone(&alone, point, root);
    }
}

/// An unarmed profile records the same bundle before and after an armed
/// run on the same thread, and its tape holds no chaos decision, so the
/// armed state ends with its run.
#[test]
fn an_unarmed_run_after_an_armed_one_records_its_own_bundle() {
    let (_, before, faulted) = rooted("faulted", PUBLISHED);
    assert_eq!(counted(&faulted), [Census::default(); Point::ALL.len()]);
    let (_, _, contended) = rooted("contended", PUBLISHED);
    assert!(counted(&contended).iter().any(|point| point.fired > 0));
    let (_, after, again) = rooted("faulted", PUBLISHED);
    assert_eq!(after, before);
    assert_eq!(again.tape, faulted.tape);
}

/// On roots where a fired point refused the upload `Contended`,
/// `contended-acked` fails through the rule for an upload collected as
/// published without its result. On the same roots `contended` records
/// no failure and ends unsuccessful under `the upload published` before
/// its no-progress limit, its upload refused and never read back, and
/// `faulted`, the same plan unarmed, passes, so the refusal came from a
/// fired point. On a root whose upload publishes, the control's plant
/// takes no effect and its run ends unsuccessful under the rule for a
/// plant that took no effect.
#[test]
fn the_contended_control_fails_through_its_named_check() {
    let failure = Failure::Violation(
        Obligation::History,
        "an upload collected as published without its result",
    );
    let identities =
        [Site::Run, Site::Settled].map(|site| FailureIdentity::of_failure(&failure, site));
    let no_progress = manifest("contended", 1).count("no_progress");
    for root in REFUSED {
        let (_, _, control) = rooted("contended-acked", root);
        match FIRED_ALONE.iter().find(|(_, alone)| *alone == root) {
            Some(&(point, _)) => fires_alone(&control, point, root),
            None => assert!(
                counted(&control).iter().any(|point| point.fired > 0),
                "root {root} fires a point"
            ),
        }
        assert_eq!(
            control.violation,
            Some(super::failure_code(&failure)),
            "root {root}"
        );
        let identity = violated(&control).expect("a complete violation with its identity");
        assert!(identities.contains(&identity), "root {root}: {identity:?}");
        assert_eq!(
            premise(Plant::ContendedAsSuccess, &control),
            Some(true),
            "root {root}"
        );
        let (terminal, _, contended) = rooted("contended", root);
        assert_eq!(contended.violation, None, "root {root}");
        assert!(
            matches!(
                terminal,
                Terminal::Complete {
                    outcome: Outcome::Unsuccessful,
                    ..
                }
            ),
            "root {root}: {terminal:?}"
        );
        assert_eq!(
            super::unsuccessful_rule(&contended).as_deref(),
            Some(super::UPLOAD_PUBLISHED),
            "root {root}"
        );
        assert!(
            contended.work.turns < no_progress,
            "root {root}: {} turns",
            contended.work.turns
        );
        let (terminal, _, _) = rooted("faulted", root);
        assert!(terminal.counts(), "faulted root {root}: {terminal:?}");
    }
    let (terminal, _, missed) = rooted("contended-acked", PUBLISHED);
    assert!(
        matches!(
            terminal,
            Terminal::Complete {
                outcome: Outcome::Unsuccessful,
                ..
            }
        ),
        "{terminal:?}"
    );
    assert_eq!(missed.violation, None);
    assert_eq!(
        super::unsuccessful_rule(&missed).as_deref(),
        Some(super::super::cluster::NO_EFFECT)
    );
}

/// One goal check after the upload ended unpublished: the datagrams both
/// links queue, the device references they hold, and the reason the world
/// has not drained.
type Check = (usize, usize, Option<&'static str>);

thread_local! {
    static CHECKS: std::cell::RefCell<Vec<Check>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// `contended`'s goal, recording a [`Check`] in [`CHECKS`] each time it is
/// asked after the upload ended unpublished.
fn goal_recording_links(world: &Mixed<'_, '_, '_>) -> bool {
    let done = super::read_or_unpublished(world);
    if world.unpublished() {
        let (mut queued, mut held) = (0, 0);
        for net in &world.scene.nets {
            let net = net.borrow();
            queued += net.pending(0) + net.pending(1);
            held += net.nic_held();
        }
        let why = super::super::relation::undrained(world);
        CHECKS.with_borrow_mut(|checks| checks.push((queued, held, why)));
    }
    done
}

/// A refused run finishes only once both links are empty: no datagram
/// queued for this turn or a later one, and no device reference held.
/// After its refusal, root 43 reaches a check where a queued datagram alone
/// keeps the world undrained, root 7 one where a held reference alone does,
/// and root 5 one with both, which the queue's reason names first.
#[test]
fn a_refused_run_finishes_with_both_links_empty() {
    const QUEUED: &str = "a datagram was in flight";
    const HELD: &str = "a link held a transmit's reference";
    // Each root, whether its check queues a datagram and holds a reference,
    // and the reason the check gives.
    let shapes = [
        (43, true, false, QUEUED),
        (7, false, true, HELD),
        (5, true, true, QUEUED),
    ];
    for (root, queues, holds, reason) in shapes {
        let mut manifest = manifest("contended", 1);
        manifest.root = root;
        CHECKS.take();
        let ran = rerun_until(&manifest, goal_recording_links);
        assert_eq!(ran.report.end, End::Done, "root {root}");
        let checks = CHECKS.take();
        assert!(
            checks.iter().any(|&(queued, held, why)| {
                (queued > 0, held > 0) == (queues, holds) && why == Some(reason)
            }),
            "root {root}: no check after the refusal has this shape under `{reason}`: {checks:?}"
        );
        assert_eq!(
            checks.last(),
            Some(&(0, 0, None)),
            "root {root}: queued datagrams, held references and the reason at the goal"
        );
    }
}

thread_local! {
    static HELD: std::cell::RefCell<Vec<(usize, usize)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// `contended`'s goal, recording in [`HELD`], each time it is asked, the
/// fill reservations the storage's shards count and the engine credits its
/// lease report counts.
fn goal_recording_reservations(world: &Mixed<'_, '_, '_>) -> bool {
    let storage = world.scene.storage;
    let fills = (0..64)
        .filter_map(|shard| storage.shard_report(crate::index::ShardIndex(shard)))
        .map(|report| report.reserved)
        .sum();
    let credits = storage.lease_report().map_or(0, |report| report.reserved);
    HELD.with_borrow_mut(|held| held.push((fills, credits)));
    super::read_or_unpublished(world)
}

/// A run whose upload a fired point refused finishes with no fill
/// reservation in a shard's count and no engine credit reserved, so the
/// refusal returned what the upload's reservation took.
#[test]
fn a_refused_run_finishes_with_no_fill_reservation_and_no_credit() {
    for root in REFUSED {
        let mut manifest = manifest("contended", 1);
        manifest.root = root;
        HELD.take();
        let ran = rerun_until(&manifest, goal_recording_reservations);
        assert_eq!(ran.report.end, End::Done, "root {root}");
        assert_eq!(
            HELD.take().last(),
            Some(&(0, 0)),
            "root {root}: fill reservations and engine credits at the goal"
        );
    }
}

#[test]
fn the_contended_plant_acts_exactly_where_the_upload_ends_contended() {
    let reran = |profile: &str, root: u64| {
        let mut manifest = manifest(profile, 1);
        manifest.root = root;
        rerun(&manifest)
    };
    for root in REFUSED {
        let healthy = reran("contended", root);
        let put = healthy.put.map(|(outcome, _)| outcome);
        assert_eq!(
            put,
            Some(Some(UploadOutcome::Failed(Status::Contended))),
            "root {root}"
        );
        assert_eq!(healthy.get, None, "root {root}: the reader issues no GET");
        let control = reran("contended-acked", root);
        assert_eq!(
            control.settled.first,
            Some(Failure::Violation(
                Obligation::History,
                "an upload collected as published without its result"
            )),
            "root {root}"
        );
        assert!(control.acted, "root {root}: the check judged the plant");
    }
    assert!(
        reran("contended", PUBLISHED).get.is_some(),
        "the reader issues its GET once the upload publishes"
    );
    let missed = reran("contended-acked", PUBLISHED);
    assert_eq!(missed.settled.first, None);
    assert!(!missed.acted, "a published upload leaves the plant idle");
}

#[test]
fn only_the_contended_profiles_arm_and_an_armed_plan_records_one_more_byte() {
    let mut armed = Vec::new();
    for entry in &super::super::catalog::FIXED {
        let Some((_, plan, _)) = named(entry.name, 1) else {
            continue;
        };
        if !plan.chaos {
            continue;
        }
        armed.push(entry.name);
        let block = Plan {
            upload_reads: true,
            ..plan
        };
        for plan in [plan, block] {
            let record = plan.record();
            let unarmed = Plan {
                chaos: false,
                ..plan
            };
            assert_eq!(
                record,
                [unarmed.record(), vec![0xF1]].concat(),
                "{}",
                entry.name
            );
        }
        assert!(block.record().contains(&0xF0), "{}", entry.name);
    }
    assert_eq!(armed, ["contended", "contended-acked"]);
}

#[test]
fn an_armed_run_arms_exchange_lost_from_the_storages_lease_limit() {
    use crate::sim::chaos::{EXCHANGE_LOST_LEASE_LIMIT, armed_odds, sites};
    use crate::sim::choice::Chooser;
    use crate::storage::owner_fixture::{storage_leasing, storage_shaped_as};
    const INDEX: u16 = super::super::INDEX;
    assert_eq!(armed_odds(), None);
    for (limit, odds) in [(1, [4, 4, 0]), (2, [4; 3]), (16, [4; 3])] {
        assert_eq!(limit >= EXCHANGE_LOST_LEASE_LIMIT, odds[2] != 0);
        let storage = storage_leasing(limit);
        let mut chooser = Chooser::fed(&sites(INDEX), Vec::new());
        let incarnation = chooser.launch(INDEX);
        let draws = std::rc::Rc::new(std::cell::RefCell::new(chooser));
        let armed = super::super::arm_over(&draws, &storage, incarnation);
        assert_eq!(armed_odds(), Some(odds), "a limit of {limit}");
        assert_eq!(armed.disarm(), None);
        assert_eq!(armed_odds(), None);
    }
    let (_, plan, _) = named("contended", PUBLISHED).unwrap();
    let (shape, chunk_len) = plan.geometry.shape();
    let root = storage_shaped_as(shape, chunk_len).root_descriptor();
    assert_eq!(root.unwrap().lease_limit, 16, "the armed world's limit");
}

/// The choices each hook call streamed: setup's, each clock move's and
/// each turn's.
#[derive(Default)]
struct Streams {
    setup: Vec<u8>,
    clocks: Vec<Vec<u8>>,
    turns: Vec<Vec<u8>>,
    /// The bounds the points were armed with after each turn.
    armed: Vec<Option<[u64; Point::ALL.len()]>>,
}

impl crate::sim::turn::Hook for Streams {
    fn begin(&mut self, _: &[u8], choices: &[u8]) {
        self.setup = choices.to_vec();
    }

    fn clock(&mut self, choices: &[u8], _: u64, _: &[crate::sim::trace::Event]) {
        self.clocks.push(choices.to_vec());
    }

    fn turn(&mut self, choices: &[u8], _: &crate::sim::turn::Turn, _: &[crate::sim::trace::Event]) {
        self.turns.push(choices.to_vec());
        self.armed.push(crate::sim::chaos::armed_odds());
    }
}

fn chaos_decisions(choices: &[u8]) -> usize {
    crate::sim::choice::bounded_decisions(choices)
        .expect("whole decisions")
        .iter()
        .filter(|(site, _)| site.domain == crate::sim::choice::Domain::Chaos)
        .count()
}

/// An armed run decides at a point only inside the actions of its turns:
/// setup's draws before the loop, every clock move and every drain turn
/// after the goal held record no chaos decision, while earlier turns do.
#[test]
fn points_decide_only_inside_the_turns_before_the_goal() {
    const DRAIN: u32 = 30;
    let (profile, plan, goal) = named("contended", PUBLISHED).unwrap();
    let plan = Plan {
        drain: DRAIN,
        ..plan
    };
    let chooser = profile.recorder(&super::super::sites_for(&plan));
    let mut streams = Streams::default();
    let (ran, _, _) = super::super::mixed_run(
        chooser,
        &profile,
        plan,
        goal,
        super::super::LIMITS,
        &mut streams,
    );
    assert_eq!(ran.report.end, crate::sim::turn::End::Done);
    assert_eq!(chaos_decisions(&streams.setup), 0, "setup");
    assert!(
        streams
            .clocks
            .iter()
            .all(|choices| chaos_decisions(choices) == 0)
    );
    let (before, drained) = streams.turns.split_at(streams.turns.len() - DRAIN as usize);
    assert!(drained.iter().all(|choices| chaos_decisions(choices) == 0));
    assert!(before.iter().any(|choices| chaos_decisions(choices) > 0));
    assert_eq!(streams.armed.len(), streams.turns.len());
    assert!(
        streams.armed.iter().all(|odds| *odds == Some([4; 3])),
        "every turn of the run is armed at each row's odds: {:?}",
        streams.armed.first()
    );
    assert_eq!(crate::sim::chaos::armed_odds(), None, "the run disarmed");
}

/// An armed run whose chooser never registered the points' sites ends as
/// a harness defect at the first reach, which fires nothing.
#[test]
fn an_unregistered_point_ends_the_armed_run_as_a_defect() {
    use crate::sim::choice::{ChoiceError, Defect, Domain};
    let (profile, plan, goal) = named("contended", PUBLISHED).unwrap();
    let chooser = profile.recorder(&super::super::sites());
    let (ran, _, _) =
        super::super::mixed_run(chooser, &profile, plan, goal, super::super::LIMITS, &mut ());
    let crate::sim::turn::End::Defect(crate::sim::turn::Defect::Choice(
        ChoiceError::HarnessDefect(Defect::Unregistered(site)),
    )) = ran.report.end
    else {
        panic!("{:?}", ran.report.end);
    };
    assert_eq!(
        (site.domain, site.actor),
        (Domain::Chaos, super::super::INDEX)
    );
    assert!(
        Point::ALL
            .iter()
            .any(|point| point.site(site.actor) == site)
    );
}
