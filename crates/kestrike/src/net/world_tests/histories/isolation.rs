//! Isolation histories: the scripted owner and a peer owner of its
//! configuration, each over its own storage, device, links and clients,
//! under one turn controller, chooser, content registry and event log.
//! The scripted owner holds a read, and in H6 for PUT an upload's write,
//! through an unproven stop, which retains them. The peer then serves its
//! resident object exactly to its own client within the history's bound,
//! and after the peer served, the stopped owner still holds every request,
//! read buffer, submitted read and device command it held when the peer's
//! GET began, its held GET still waits and its volume's quiesce proves no
//! stop.
//!
//! The controls plant one defect each: the GET for the resident object
//! issued through the stopped owner's uploading client instead of the
//! peer's client, which the stopped owner serves no bytes for within the
//! bound, and the stopped owner's requests read as returned after the peer
//! served, which the isolation check refuses.

use crate::storage::QuiesceProgress;

use super::super::super::owner_tests::read_custody;
use super::super::super::put_tests::Scene;
use super::*;

/// The isolation check's rule for a stopped owner whose accounts moved.
const RETURNED: &str = "a failed owner returned custody its unproven stop retained";

/// The isolation check's rule for a GET beside the stopped owner that
/// missed its exact bytes or its bound.
const STARVED: &str = "a healthy owner served no exact bytes";

const UNPROVEN: &str = "a failed owner's unproven stop read as proven";

/// What the isolation check compares of the stopped owner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Accounts {
    /// Live requests.
    live: u32,
    /// Read-response buffers its arena holds out.
    buffers: u32,
    writes: u32,
    /// Read commands its volume submitted, completed and failed.
    reads: (u64, u64, u64),
    /// Commands outstanding on its device.
    commands: usize,
    /// Frames sent and failed.
    sent: u64,
}

/// The client a GET beside the stopped owner went through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Via {
    /// The peer's GET client.
    Peer,
    /// The stopped owner's uploading client.
    Stopped,
}

/// The peer owner's scene.
fn peer<'w, 's, 'm>(world: &'w Mixed<'_, 's, 'm>) -> &'w Scene<'s, 'm> {
    &world.peer.as_ref().expect("a two-owner scene").scene
}

fn peer_mut<'w, 's, 'm>(world: &'w mut Mixed<'_, 's, 'm>) -> &'w mut Scene<'s, 'm> {
    &mut world.peer.as_mut().expect("a two-owner scene").scene
}

/// The peer's GET client holds an active session.
fn peer_active(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    peer(world).clients[1].state() == super::super::super::client::SessionState::Active
}

fn accounts(world: &Mixed<'_, '_, '_>) -> Accounts {
    let volume = world.scene.owner.volume_report();
    let report = world.scene.owner.report();
    let arena = world
        .scene
        .buffers
        .expect("the scripted owner's buffer arena");
    let receive = arena.report(crate::storage::PoolKind::ReceiveWrite);
    Accounts {
        live: world.scene.owner.census().live(),
        buffers: read_custody(arena),
        writes: receive.count - receive.free - receive.retired,
        reads: (
            volume.reads_submitted,
            volume.reads_done,
            volume.reads_failed,
        ),
        commands: world.scene.control.outstanding(),
        sent: report.sent + report.failed,
    }
}

/// The unproven stop, with the stopped owner's accounts as they stood
/// before it kept for the GET beside it.
fn isolated_stop(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.at_stop = Some(accounts(world));
    unproven_stop(world, now)
}

/// The GET beside the stopped owner through `via`'s client. The stopped
/// owner's read buffers, read commands and sends stand as they did before
/// its stop; the issue starts the bound, wakes the run once the bound
/// passes and records the stopped owner's accounts.
fn issue_beside(world: &mut Mixed<'_, '_, '_>, now: u64, via: Via) -> u64 {
    let Some(stopped) = world.history.at_stop else {
        world
            .first
            .record(Failure::Unsuccessful("the stop kept the owner's accounts"));
        return STAY;
    };
    let current = accounts(world);
    let held = (current.buffers, current.writes, current.reads, current.sent);
    if current.live < stopped.live
        || held != (stopped.buffers, stopped.writes, stopped.reads, stopped.sent)
    {
        fail(world, Obligation::Isolation, RETURNED);
        return STAY;
    }
    let client = match via {
        Via::Peer => &mut peer_mut(world).clients[1],
        Via::Stopped => &mut world.scene.clients[0],
    };
    let Ok(id) = client.get(key(1), 0, 1 << 20, now, super::super::WAIT_US) else {
        return STAY;
    };
    world.history.beside = Some((id, via));
    world.history.since = now;
    world.history.wake = Some(now + BOUND_US + 1);
    world.history.at_beside = Some(current);
    mark(
        world,
        match via {
            Via::Peer => "the healthy owner's GET began beside the stopped one",
            Via::Stopped => "the GET beside the stopped owner went through its own client",
        },
    )
}

fn beside_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    issue_beside(world, now, Via::Peer)
}

/// A control: the GET beside the stopped owner goes through the stopped
/// owner's uploading client instead of the peer's GET client.
fn beside_get_routed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    issue_beside(world, now, Via::Stopped)
}

fn beside_decided_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    let (id, via) = world
        .history
        .beside
        .expect("the GET beside the stopped owner");
    let client = match via {
        Via::Peer => &peer(world).clients[1],
        Via::Stopped => &world.scene.clients[0],
    };
    client.outcome(id).is_some() || now > world.history.since + BOUND_US
}

/// The GET beside the stopped owner's outcome and every byte it delivered,
/// after which its request retires.
fn beside_result(world: &mut Mixed<'_, '_, '_>) -> (Option<Outcome>, Vec<u8>) {
    let (id, via) = world
        .history
        .beside
        .expect("the GET beside the stopped owner");
    let (client, logical, owner) = match via {
        Via::Peer => (&mut peer_mut(world).clients[1], 1, 1),
        Via::Stopped => (&mut world.scene.clients[0], 0, 0),
    };
    let bytes = drain(client, id);
    let outcome = client.outcome(id);
    let _ = client.retire(id);
    if let Some(outcome) = outcome {
        world.collected.add(super::super::bundle::Collected::Get(
            logical, owner, outcome,
        ));
    }
    (outcome, bytes)
}

/// The GET beside the stopped owner completes with the resident object's
/// exact bytes within the bound of its issue.
fn beside_exact(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let (outcome, bytes) = beside_result(world);
    judge_served(world, now, outcome, &bytes)
}

fn judge_served(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    outcome: Option<Outcome>,
    bytes: &[u8],
) -> u64 {
    if !exact_within(world, now, outcome, bytes) {
        return fail(world, Obligation::Isolation, STARVED);
    }
    mark(
        world,
        "a healthy owner served exact bytes beside a stopped one",
    )
}

/// After the peer served, the stopped owner's accounts stand as they did
/// when the peer's GET began, every command the history held stays pending,
/// its held GET has no answer from it, and its volume's quiesce proves no
/// stop.
fn stopped_kept(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let live = world.scene.owner.census().live();
    judge_kept(world, live)
}

/// A control: the stopped owner's requests are read as returned, as an
/// owner releasing its unproven stop's share would leave them.
fn stopped_returned(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_kept(world, 0)
}

fn judge_kept(world: &mut Mixed<'_, '_, '_>, live: u32) -> u64 {
    let unproven = matches!(
        world.scene.owner.quiesce(),
        Some(QuiesceProgress::Draining { .. } | QuiesceProgress::Unproven { .. })
    );
    if !unproven {
        return fail(world, Obligation::Isolation, UNPROVEN);
    }
    let Some(beside) = world.history.at_beside else {
        world.first.record(Failure::Unsuccessful(
            "the GET beside kept the owner's accounts",
        ));
        return 0;
    };
    let kept = Accounts {
        live,
        ..accounts(world)
    } == beside;
    // The stopped owner sent nothing, so a held GET that ended did so at
    // its own client's deadline.
    let unanswered = world.gets[1].as_ref().is_some_and(|get| {
        matches!(
            world.scene.clients[1].outcome(get.id).or(get.outcome),
            None | Some(Outcome::Failed(Status::TimedOut))
        )
    });
    if !kept || !unanswered || !commands_pending(world) {
        return fail(world, Obligation::Isolation, RETURNED);
    }
    mark(
        world,
        "the stopped owner kept the custody its unproven stop retained",
    )
}

/// The obligation each isolation check's mark judges.
pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (
        "a healthy owner served exact bytes beside a stopped one",
        Obligation::Isolation,
    ),
    (
        "the stopped owner kept the custody its unproven stop retained",
        Obligation::Isolation,
    ),
];

/// The stopped owner's retained custody, then the peer's exact read beside
/// it and the stopped owner's accounts after it.
const ISOLATED: [Step; 6] = [
    step("stop", always, isolated_stop),
    step("stop-retained", owner_polled, stop_retained),
    step("beside-get", peer_active, beside_get),
    step("beside-read", beside_decided_or_late, beside_exact),
    step("isolated", always, stopped_kept),
    JUDGE,
];

/// H6 for GET: the stopped owner holds its old GET's read.
const H6_GET: [Step; 9] = joined(
    [
        step("arm", always, arm),
        step("old-get", active_get, old_get),
        step("old-read-held", read_held, mark_read_held),
    ],
    ISOLATED,
);

const H6_GET_ROUTED: [Step; 9] = replaced(
    H6_GET,
    "beside-get",
    step("beside-get-routed", active_put, beside_get_routed),
);

const H6_GET_RETURNED: [Step; 9] = replaced(
    H6_GET,
    "isolated",
    step("isolated-returned", always, stopped_returned),
);

/// H6 for PUT: the stopped owner also holds an upload's write after its
/// DATA was supplied.
const H6_PUT: [Step; 13] = joined(
    [
        step("arm", always, arm_writes),
        step("put-begin", active_put, put_begin),
        step("put-prepare", always, put_prepare),
        step("put-supply", always, put_supply),
        step("write-held", write_held, mark_write_held),
        step("old-get", active_get, old_get),
        step("old-read-held", read_held, mark_read_held),
    ],
    ISOLATED,
);

const H6_WITNESSES: &[&str] = &[
    "old read held",
    "owner stopped with a read held",
    "the stop retained its custody",
    "a healthy owner served exact bytes beside a stopped one",
    "the stopped owner kept the custody its unproven stop retained",
];
const H6_PUT_WITNESSES: &[&str] = &[
    "upload DATA supplied",
    "owner write held",
    "old read held",
    "owner stopped with a read held",
    "the stop retained its custody",
    "a healthy owner served exact bytes beside a stopped one",
    "the stopped owner kept the custody its unproven stop retained",
];

const ISOLATION: &[Obligation] = &[Obligation::Custody, Obligation::Isolation];

pub(super) const PAIRED: [History; 4] = [
    paired(history(
        "h6-get",
        &H6_GET,
        H6_WITNESSES,
        ISOLATION,
        Expect::Pass,
    )),
    paired(uploading(
        history("h6-put", &H6_PUT, H6_PUT_WITNESSES, ISOLATION, Expect::Pass),
        1,
    )),
    paired(control(
        history(
            "h6-get-routed",
            &H6_GET_ROUTED,
            H6_WITNESSES,
            ISOLATION,
            Expect::Violation(Obligation::Isolation, STARVED),
        ),
        &[
            "old read held",
            "owner stopped with a read held",
            "the stop retained its custody",
        ],
    )),
    paired(control(
        history(
            "h6-get-returned",
            &H6_GET_RETURNED,
            H6_WITNESSES,
            ISOLATION,
            Expect::Violation(Obligation::Isolation, RETURNED),
        ),
        &[
            "old read held",
            "owner stopped with a read held",
            "a healthy owner served exact bytes beside a stopped one",
        ],
    )),
];

#[cfg(test)]
mod tests {
    use crate::oracle::Obligation;
    use crate::sim::trace::load;

    use super::super::super::super::audit::{Record, Source, Verdict};
    use super::super::super::super::observe::Failure;
    use super::super::super::bundle::{AUDIT, FAILURE, admit, change_published, observed, traced};
    use super::super::super::replay::{Replayed, replay};
    use super::super::super::{Events, LIMITS, PEER_LINKS, Plan, Ran, mixed_run, sites_for};
    use super::super::tests::manifest;
    use super::*;

    #[test]
    fn every_isolation_history_ends_as_declared_and_replays_equal() {
        for (name, rule) in [
            ("h6-get-routed", "a healthy owner served no exact bytes"),
            (
                "h6-get-returned",
                "a failed owner returned custody its unproven stop retained",
            ),
        ] {
            let declared = PAIRED.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(Obligation::Isolation, rule),
                "{name}"
            );
            assert!(!declared.premise.is_empty(), "{name} declares its premise");
        }
        for history in &PAIRED {
            let bytes = traced(
                admit(&manifest(history.name)).expect("admitted"),
                Vec::new(),
            )
            .sink;
            let loaded = load(&bytes, 1_000_000).expect("a loadable bundle");
            assert_eq!(
                history.ends_as_declared(&loaded),
                Ok(()),
                "{}",
                history.name
            );
            let composed = observed(&loaded.events)
                .composed
                .expect("a stop composition");
            assert_eq!(
                (composed.owners, composed.clients),
                (2, 4),
                "{} records the two-owner composition",
                history.name
            );
            assert_eq!(
                replay(&bytes).expect("a replay").0,
                Replayed::Reproduced,
                "{}",
                history.name
            );
        }
    }

    fn ran(name: &str, script: &'static [Step]) -> (Ran, Option<Failure>) {
        let (ran, first, _) = emitted(name, script, 0);
        (ran, first)
    }

    fn emitted(name: &str, script: &'static [Step], drain: u32) -> (Ran, Option<Failure>, Events) {
        let (profile, plan, goal) = super::super::named(name, 3).expect(name);
        let plan = Plan {
            script,
            drain,
            ..plan
        };
        let chooser = profile.recorder(&sites_for(&plan));
        let mut events = Events::default();
        let (ran, first, _) = mixed_run(chooser, &profile, plan, goal, LIMITS, &mut events);
        (ran, first, events)
    }

    fn hold_spare(world: &mut Mixed<'_, '_, '_>, kind: crate::storage::PoolKind) {
        let arena = world.scene.buffers.expect("the scripted owner's arena");
        let spare = arena.acquire(kind).expect("a spare buffer");
        world.history.pool.push(spare);
    }

    fn beside_changed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        let (outcome, mut bytes) = beside_result(world);
        bytes[0] ^= 1;
        judge_served(world, now, outcome, &bytes)
    }

    fn past_bound(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
        now > world.history.since + BOUND_US
    }

    fn stopped_ending_reads(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        for &token in &world.history.held {
            world.scene.control.release(token);
            world.scene.control.post(token);
        }
        stopped_kept(world, now)
    }

    fn stop_returning_buffer(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        hold_spare(world, crate::storage::PoolKind::ReadResponse);
        let stopped = isolated_stop(world, now);
        world.history.pool.clear();
        stopped
    }

    fn beside_holding_write(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        hold_spare(world, crate::storage::PoolKind::ReceiveWrite);
        beside_get(world, now)
    }

    fn kept_after_write_returned(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        world.history.pool.clear();
        stopped_kept(world, now)
    }

    fn old_timed_out(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
        world.gets[1].as_ref().is_some_and(|get| {
            world.scene.clients[1].outcome(get.id).or(get.outcome)
                == Some(Outcome::Failed(Status::TimedOut))
        })
    }

    fn beside_edited(world: &mut Mixed<'_, '_, '_>, now: u64, edit: fn(&mut Accounts)) -> u64 {
        let issued = beside_get(world, now);
        edit(world.history.at_beside.as_mut().expect("the GET began"));
        issued
    }

    fn stop_edited(world: &mut Mixed<'_, '_, '_>, now: u64, edit: fn(&mut Accounts)) -> u64 {
        let stopped = isolated_stop(world, now);
        edit(world.history.at_stop.as_mut().expect("the stop's accounts"));
        stopped
    }

    fn beside_reads_moved(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        beside_edited(world, now, |accounts| accounts.reads.1 += 1)
    }

    fn beside_commands_moved(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        beside_edited(world, now, |accounts| accounts.commands += 1)
    }

    fn beside_sent_moved(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        beside_edited(world, now, |accounts| accounts.sent += 1)
    }

    fn stop_reads_moved(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        stop_edited(world, now, |accounts| accounts.reads.0 += 1)
    }

    fn stop_sent_moved(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        stop_edited(world, now, |accounts| accounts.sent += 1)
    }

    fn stop_live_raised(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        stop_edited(world, now, |accounts| accounts.live += 1)
    }

    fn peer_record_changed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        assert!(
            change_published(peer(world), 1),
            "the peer's record changed"
        );
        stopped_kept(world, now)
    }

    fn arm_peer_changed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        assert!(
            change_published(peer(world), 1),
            "the peer's record changed"
        );
        arm(world, now)
    }

    fn peer_link_unattributed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        peer(world).nets[1].borrow_mut().fail_unattributed();
        beside_get(world, now)
    }

    /// Closes the peer with its GET client's next GET bound for it, and
    /// wakes the run a link turn later.
    fn kept_peer_closed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        let peer = peer_mut(world);
        let _ = peer.owner.close(now);
        peer.clients[1]
            .get(key(1), 0, 1 << 20, now, super::super::super::WAIT_US)
            .expect("an admitted GET");
        world.history.wake = Some(now + 10 * super::super::super::LINK_TURN_US);
        stopped_kept(world, now)
    }

    fn woken(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
        world.history.wake.is_some_and(|wake| now >= wake)
    }

    const fn planted(script: [Step; 9], name: &str, with: Step) -> [Step; 9] {
        replaced(script, name, with)
    }

    const SERVED_CHANGED: [Step; 9] = planted(
        H6_GET,
        "beside-read",
        step(
            "beside-read-changed",
            beside_decided_or_late,
            beside_changed,
        ),
    );
    const SERVED_LATE: [Step; 9] = planted(
        H6_GET,
        "beside-read",
        step("beside-read-late", past_bound, beside_exact),
    );
    const READS_ENDED: [Step; 9] = planted(
        H6_GET,
        "isolated",
        step("isolated-reads-ended", always, stopped_ending_reads),
    );
    const BUFFER_RETURNED: [Step; 9] = planted(
        H6_GET,
        "stop",
        step("stop-returning-buffer", always, stop_returning_buffer),
    );
    const WRITE_RETURNED: [Step; 13] = replaced(
        replaced(
            H6_PUT,
            "beside-get",
            step(
                "beside-get-holding-write",
                peer_active,
                beside_holding_write,
            ),
        ),
        "isolated",
        step("isolated-write-returned", always, kept_after_write_returned),
    );
    const TIMED_OUT: [Step; 9] = planted(
        H6_GET,
        "isolated",
        step("isolated-timed-out", old_timed_out, stopped_kept),
    );
    const BESIDE_READS: [Step; 9] = planted(
        H6_GET,
        "beside-get",
        step("beside-get-reads", peer_active, beside_reads_moved),
    );
    const BESIDE_COMMANDS: [Step; 9] = planted(
        H6_GET,
        "beside-get",
        step("beside-get-commands", peer_active, beside_commands_moved),
    );
    const BESIDE_SENT: [Step; 9] = planted(
        H6_GET,
        "beside-get",
        step("beside-get-sent", peer_active, beside_sent_moved),
    );
    const STOP_READS: [Step; 9] =
        planted(H6_GET, "stop", step("stop-reads", always, stop_reads_moved));
    const STOP_SENT: [Step; 9] =
        planted(H6_GET, "stop", step("stop-sent", always, stop_sent_moved));
    const STOP_LIVE: [Step; 9] =
        planted(H6_GET, "stop", step("stop-live", always, stop_live_raised));
    const PEER_CHANGED: [Step; 9] = planted(
        H6_GET,
        "isolated",
        step("isolated-peer-changed", always, peer_record_changed),
    );
    const PEER_CHANGED_EARLY: [Step; 9] = planted(
        H6_GET,
        "arm",
        step("arm-peer-changed", always, arm_peer_changed),
    );
    const PEER_UNATTRIBUTED: [Step; 9] = planted(
        H6_GET,
        "beside-get",
        step(
            "beside-get-unattributed",
            peer_active,
            peer_link_unattributed,
        ),
    );
    const PEER_CLOSED: [Step; 9] = replaced(
        planted(
            H6_GET,
            "isolated",
            step("isolated-peer-closed", always, kept_peer_closed),
        ),
        "judge",
        step("judge-woken", woken, judge),
    );

    #[test]
    fn each_isolation_clause_refuses_its_planted_defect() {
        let (_, first) = ran("h6-get", &H6_GET);
        assert_eq!(first, None, "the unplanted script passes");
        let (ran_out, first) = ran("h6-get", &TIMED_OUT);
        assert_eq!(
            (ran_out.report.end, first),
            (crate::sim::turn::End::Done, None),
            "a held GET ended at its own deadline is unanswered"
        );
        for (name, script, rule) in [
            (
                "h6-get",
                &SERVED_CHANGED[..],
                "a healthy owner served no exact bytes",
            ),
            (
                "h6-get",
                &SERVED_LATE[..],
                "a healthy owner served no exact bytes",
            ),
            (
                "h6-get",
                &READS_ENDED[..],
                "a failed owner returned custody its unproven stop retained",
            ),
            (
                "h6-get",
                &BUFFER_RETURNED[..],
                "a failed owner returned custody its unproven stop retained",
            ),
            (
                "h6-put",
                &WRITE_RETURNED[..],
                "a failed owner returned custody its unproven stop retained",
            ),
            (
                "h6-get",
                &BESIDE_READS[..],
                "a failed owner returned custody its unproven stop retained",
            ),
            (
                "h6-get",
                &BESIDE_COMMANDS[..],
                "a failed owner returned custody its unproven stop retained",
            ),
            (
                "h6-get",
                &BESIDE_SENT[..],
                "a failed owner returned custody its unproven stop retained",
            ),
            (
                "h6-get",
                &STOP_READS[..],
                "a failed owner returned custody its unproven stop retained",
            ),
            (
                "h6-get",
                &STOP_SENT[..],
                "a failed owner returned custody its unproven stop retained",
            ),
            (
                "h6-get",
                &STOP_LIVE[..],
                "a failed owner returned custody its unproven stop retained",
            ),
        ] {
            let (_, first) = ran(name, script);
            assert_eq!(
                first,
                Some(Failure::Violation(Obligation::Isolation, rule)),
                "{script:?}"
            );
        }
        // A refusal at the GET beside leaves its step in place, so a run
        // that drains past its goal reaches no step that needs the GET.
        let (_, first, _) = emitted("h6-get", &BUFFER_RETURNED, 1);
        assert_eq!(
            first,
            Some(Failure::Violation(
                Obligation::Isolation,
                "a failed owner returned custody its unproven stop retained"
            ))
        );
    }

    #[test]
    fn the_peer_joins_the_boundary_check_and_the_audit() {
        let (_, first) = ran("h6-get", &PEER_CHANGED);
        assert!(
            matches!(first, Some(Failure::Violation(Obligation::Bytes, _))),
            "{first:?}"
        );
        let (_, first, events) = emitted("h6-get", &PEER_CHANGED_EARLY, 0);
        assert!(
            matches!(first, Some(Failure::Violation(Obligation::Bytes, _))),
            "{first:?}"
        );
        assert!(
            events.0.iter().any(|event| event.kind == FAILURE),
            "a stopped boundary reported the peer's record"
        );
        let (ran, _, events) = emitted("h6-get", &PEER_UNATTRIBUTED, 0);
        let peer_link = super::super::super::peer::NETS + 1;
        assert!(
            events
                .0
                .iter()
                .any(|event| event.kind == AUDIT && event.payload[0] == peer_link),
            "the peer link's audit record reaches the event log"
        );
        assert!(
            !ran.audits[usize::from(peer_link)].is_empty(),
            "the run keeps the peer link's audit records"
        );
        assert!(
            matches!(
                ran.audit,
                Verdict::Fail(Record {
                    source: Source::Link { actor, .. },
                    ..
                }) if actor == PEER_LINKS[1]
            ),
            "{:?}",
            ran.audit
        );
    }

    #[test]
    fn a_closed_peer_with_inbound_datagrams_lets_time_advance() {
        let (ran, first) = ran("h6-get", &PEER_CLOSED);
        assert_eq!((ran.report.end, first), (crate::sim::turn::End::Done, None));
    }

    #[test]
    fn the_mixed_runner_runs_a_two_owner_plan() {
        let (profile, plan, goal) = super::super::named("h6-get", 3).expect("h6-get");
        let ran = super::super::super::mixed(&profile, plan, goal);
        assert_eq!(ran.report.end, crate::sim::turn::End::Done);
    }

    #[test]
    fn a_relaunch_keeps_only_the_peers_beside_get() {
        let id = crate::net::requests::RequestId::from_wire(7);
        for (via, kept) in [(Via::Peer, true), (Via::Stopped, false)] {
            let mut state = State {
                beside: Some((id, via)),
                at_stop: Some(Accounts::default()),
                at_beside: Some(Accounts::default()),
                ..State::default()
            };
            state.relaunched();
            assert_eq!(state.beside.is_some(), kept, "{via:?}");
            assert_eq!((state.at_stop, state.at_beside), (None, None), "{via:?}");
        }
    }
}
