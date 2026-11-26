//! Two families judge the rule RULE: SS1 over the owner's request shares, and SS2 over the volume's
//! read share.
//!
//! SS1: a peer whose request share has room completes its GET exactly and in time while another
//! peer's share is saturated. Property: an eligible peer's GET starved behind a saturated share. The
//! owner charges each request to its own peer's share (`RequestTable::room`), so a peer whose share
//! has room completes its GET exactly and in time while another peer's share is full. The rule this
//! file judges is RULE below, which `peer_exact` and `peer_read_in_bound` of `histories.rs` raise under
//! `Obligation::Progress`.
//!
//! SS1's histories run the steps of H4 for GET (`histories.rs`, `H4_GET`) with no
//! link fault. The owner gives each of two peers a share of two requests in a table of four slots.
//!
//! - `ss1-get-beside-a-saturated-share`: the device holds every read, the GET client issues two
//!   GETs of key 1, which fill its share once both reads are held, and a third past the share. The other
//!   peer then issues one GET of the resident object. The judge step fails with the rule unless that GET
//!   ends `Complete` with the resident's exact bytes within 200 ms of its issue; it runs while the device
//!   still holds both saturating reads, which STILL_HELD witnesses, and `peer_exact` also requires each
//!   peer's charge within its own share. The saturated share and its held reads are the history's premise:
//!   a failure without them ends the run unsuccessful. Released, the saturating GETs read exactly.
//! - `ss1-get-beside-an-open-share`: the same steps with the device holds never
//!   armed, so the two GETs complete and no share stays saturated; the other peer's GET meets the same
//!   bound and exact bytes. The GET client's first two GETs fit its own share whatever the other peer
//!   holds, so each is an eligible peer's GET as well and is judged by the same rule.
//! - `ss1-get-beside-a-drained-share` falsifies STILL_HELD: the history releases both saturating
//!   reads and waits for device completion before the other peer's GET, and the run ends
//!   unsuccessful.
//! - In the `ss1-open-share-peer-late` control, the sibling's judge fails through RULE because it
//!   reads the other peer's GET two bounds after its decision.
//! - In the `ss1-open-share-get-read-as-refused` control, the sibling's healed step fails through
//!   RULE because it reads the GET client's first GET as refused.
//! - In the `ss1-open-share-get-past-read-as-missing` control, the sibling's healed step fails
//!   through HEALED_INEXACT because it reads the GET client's third GET as `Missing`.
//!
//! SS2 judges the volume's read share through the same rule. Property: the obligation record
//! `tick-cursor-moves-only-on-a-call-that-serves` of `verification/obligations.json`, whose
//! transition names waiting reads under a one-slot read share: every waiting read submits within
//! `read_ops` calls with room, in slot order from the cursor. A GET whose read waits past its one
//! deadline while the read command it waits for keeps going to later reads is an eligible peer's GET
//! starved behind a saturated share, which RULE (array `MIXED` of `narrate/rules.rs`) states and
//! `peer_read_in_bound` of `histories.rs` raises under `Obligation::Progress`. The history judges the request's one
//! deadline, the bound RULE carries, which a waiting read served within `read_ops` trades meets; it
//! counts no calls with room and observes no slot order, so the obligation's call bound and cursor
//! order stay with the record. SS2 holds no link fault and no device hold other than its reads. The
//! world's read check (`misread`) judges the peer's GET and each traded GET on the outcome and bytes
//! the client observed before any other check. Its traded GETs each read the resident exactly, or
//! fail HEALED_INEXACT, the rule SS1's healed GETs fail through; a traded GET that ends refused
//! leaves the premise TRADED unformed. The GET client's GETs decided when the trades stop, and those
//! decided when the peer's GET is judged, are judged before the peer's verdict.
//!
//! - `ss2-peer-read-waits-for-one-command` runs over the storage whose read share is one command.
//!   The GET client's first read takes the command and is held; the peer's GET, issued with the
//!   world's wait, then waits under its kept grant (the volume's count of reads that waited rises by
//!   one). Until that GET is decided or 200 ms passed, each trade retires the GET client's decided
//!   GET, issues its next GET, sends it to the owner's end of the link, and ends the hold on the held
//!   read with its completion posted, so one owner turn applies the terminal and admits the GET. The
//!   turn frees the command in `poll_terminals` and admits the GET in `receive_batch`, before the
//!   volume's tick, and the new read takes the command at its first submit while the peer's read
//!   waits; the peer's GET ends at its deadline without its bytes and the judge fails RULE. A cache
//!   that keeps the freed command for the waiting read passes. No event runs inside a trade, so no
//!   owner turn falls between the terminal and the GET under any root. The premise TRADED records
//!   that ordering from state each build has: when the step released a read, a further datagram of
//!   the GET client was due at the owner's end of the link, and none of the traded GETs ended
//!   refused at the client by the judge, the healed step or the trade that retires it. It also
//!   records that the demand lasted: when the peer's GET reached its bound, a trade had run within
//!   two paces of that bound. Trades that stop earlier leave the device holding the command's read
//!   until the bound, whichever read the volume gave the command to, and such a run ends
//!   unsuccessful under TRADED.
//! - `ss2-peer-read-beside-three-commands` runs the same steps over the fixture storage, whose
//!   read share is three commands: the peer's read takes a free command at once, the first trade
//!   releases it, and the peer's GET completes exactly within the bound.
//! - `ss2-one-command-peer-read-served-untraded` runs the pin's steps over the one-command storage
//!   with no trade: once the peer's read waits, the step ends the hold on the GET client's read and
//!   posts its completion, the device holds no later read, and the GET client issues no further
//!   GET. The freed command has no other taker, the tick submits the waiting read, and the peer's
//!   GET completes exactly within the bound: a volume that never submits a waiting read fails RULE
//!   here.
//! - In the `ss2-three-commands-peer-late` control, the sibling's judge fails through RULE because
//!   it reads the peer's GET two bounds after its decision.
//! - In the `ss2-three-commands-trader-read-as-missing` control, the sibling's healed step fails
//!   through HEALED_INEXACT because it reads the first GET it judges as `Missing`.
//! - `ss2-peer-read-submitted-as-waiting` falsifies PEER_WAITED: it runs the pin's steps over the
//!   fixture storage, where the peer's read takes a free command, and ends unsuccessful.
//! - `ss2-three-commands-trader-read-as-refused` falsifies TRADED's refusal half: the sibling's
//!   healed step reads the first GET it judges as refused, and the run ends unsuccessful.
//! - `ss2-one-command-trade-unsent` falsifies TRADED: its trades leave the GET client's next GET
//!   in the client, and the run ends unsuccessful at the first trade.
//! - `ss2-one-command-trades-stalled` falsifies TRADED's pace: its trade step trades once and
//!   then waits for the peer's GET to be decided or late, and the run ends unsuccessful.
//! - `ss2-one-command-trader-read-as-refused-at-exit` falsifies TRADED's refusal half where the
//!   trades stop: the pin's trade step reads the first traded GET the client still holds as refused
//!   once the peer's GET is late, and the run ends unsuccessful.
//! - `ss2-one-command-peer-wait-read-as-uncounted` falsifies PEER_WAITED's count alone: over the
//!   one-command storage, where the device holds one read, the step judges the volume's count of
//!   reads that waited as unchanged since the peer's GET, and the run ends unsuccessful.
//! - In the `ss2-three-commands-trader-read-altered` control, the sibling's healed step changes the
//!   first byte of the first GET it judges after the world's read check passed it, and the run fails
//!   through HEALED_INEXACT.
//! - In the `ss2-three-commands-peer-read-altered` control, the sibling's judge changes the first
//!   byte of the peer's timely `Complete` before the world's read check, and the run fails through
//!   COMPLETE_MISREAD (`narrate/rules.rs`) under `Obligation::Bytes`, ahead of RULE.
//! - In the `ss2-three-commands-peer-late-read-altered` control, the sibling's judge reads the
//!   peer's GET two bounds late with its first byte changed, and the run fails through
//!   COMPLETE_MISREAD under `Obligation::Bytes`, ahead of the bound.
//! - In the `ss2-three-commands-trader-read-corrupted` control, the sibling's healed step changes
//!   the first byte of the first GET it judges before the world's read check, and the run fails
//!   through COMPLETE_MISREAD under `Obligation::Bytes`.
//! - In the `ss2-one-command-trader-read-corrupted-at-exit` control, the pin's trade step, once the
//!   peer's GET is late, changes the first byte of the first traded GET the client holds decided,
//!   before the world's read check, and the run fails through COMPLETE_MISREAD under
//!   `Obligation::Bytes`, ahead of RULE, the peer's verdict there. The GET the last trade released
//!   may still be undecided when the trades stop, which depends on the root, so the step is due
//!   once the client holds a traded GET decided or four trade paces passed after the peer's bound,
//!   and the control declares the premise EXIT_DECIDED, read from the client's outcomes: a run
//!   where the client holds no traded GET decided by then ends unsuccessful under it.
//! - `ss2-one-command-trader-read-as-undecided-at-exit` falsifies EXIT_DECIDED: the exit control's
//!   trade step runs once the wait ended and reads every traded GET as undecided, and the run ends
//!   unsuccessful.
//! - `ss2-one-command-peer-read-as-submitted` falsifies PEER_SUBMITTED: it runs the sibling's steps
//!   over the one-command storage, where the peer's read waits, and ends unsuccessful.
//! - `ss2-three-commands-peer-wait-read-as-counted` falsifies PEER_WAITED's held count alone: over
//!   the fixture storage, where the device holds both reads, the step judges the volume's count of
//!   reads that waited as risen by one, and the run ends unsuccessful.

use super::super::narrate::rules::COMPLETE_MISREAD;
use super::*;

/// The rule SS1 and SS2 judge.
const RULE: &str = "an eligible peer's GET starved behind a saturated share";

const STILL_HELD: &str = "saturating reads held at the peer's read";
const NEVER_ARMED: &str = "the device holds were never armed";
const NOTHING_HELD: &str = "the device held no read";
const PAST_ISSUED: &str = "a GET past the share waits in the client";
const HEALED_INEXACT: &str = "a healed saturated GET missed its exact bytes";
const LATER_SETTLED: &str = "the later GET ended exact or refused";

/// Applies `peer_exact`'s check to the other peer's GET only while both saturating reads remain
/// pending on the device at the judge step.
fn peer_exact_beside_held(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let held = world.history.held.len() >= 2 && commands_pending(world);
    if premised(world, held, STILL_HELD) == 0 {
        return 0;
    }
    peer_exact(world, now)
}

/// The sibling's first step: no hold is armed.
fn unarmed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let unarmed = !world.history.hold_reads && !world.history.hold_nic;
    premised(world, unarmed, NEVER_ARMED)
}

/// The sibling's step in the place of the held reads: the device holds none.
fn nothing_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let unheld = world.history.held.is_empty();
    premised(world, unheld, NOTHING_HELD)
}

/// The sibling's judge: the other peer's GET ends `Complete` with the resident's exact bytes within the
/// bound of its issue, the two conditions the first history's judge fails through the rule.
fn peer_exact_unsaturated(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    peer_read_judged(world, now, |_| ())
}

fn peer_unsaturated_late(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    peer_read_judged(world, now + 2 * BOUND_US, |_| ())
}

/// Marks the peer's progress once `peer_read_in_bound` of `histories.rs`
/// passes the peer's GET observed at `decided_at` with its bytes as
/// `alter` leaves them.
fn peer_read_judged(
    world: &mut Mixed<'_, '_, '_>,
    decided_at: u64,
    alter: impl FnOnce(&mut Vec<u8>),
) -> u64 {
    if !peer_read_in_bound(world, decided_at, alter) {
        return 0;
    }
    mark(world, "eligible peer progressed")
}

/// Changes the first byte of a GET's returned bytes.
fn flip_first(bytes: &mut [u8]) {
    if let Some(first) = bytes.first_mut() {
        *first ^= 1;
    }
}

/// The sibling's healed step: the GET client's first two GETs, which fit its share, each read the resident
/// exactly, and a refusal or any other ending of one is the rule; the GET issued past them reads exactly
/// or is refused with no byte, as `saturated_exact` allows.
fn unsaturated_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_unsaturated(world, |_, outcome| outcome)
}

fn unsaturated_first_refused(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_unsaturated(world, |at, outcome| match at {
        0 => Some(Outcome::Pressure(Status::RequestPressure)),
        _ => outcome,
    })
}

fn unsaturated_past_missing(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if world.history.ids.len() < 3 {
        return premised(world, false, PAST_ISSUED);
    }
    judge_unsaturated(world, |at, outcome| match at {
        2 => Some(Outcome::Missing),
        _ => outcome,
    })
}

fn judge_unsaturated(
    world: &mut Mixed<'_, '_, '_>,
    read: impl Fn(usize, Option<Outcome>) -> Option<Outcome>,
) -> u64 {
    let (mut eligible, mut rest) = (true, true);
    for (at, id) in world.history.ids.clone().into_iter().enumerate() {
        let bytes = drain(&mut world.scene.clients[1], id);
        let outcome = read(at, world.collect_get(1, id));
        let _ = world.scene.clients[1].retire(id);
        let exact = outcome == Some(Outcome::Complete) && bytes == version_a();
        let refused = matches!(outcome, Some(Outcome::Pressure(_))) && bytes.is_empty();
        if at < 2 {
            eligible &= exact;
        } else {
            rest &= exact || refused;
        }
    }
    if !eligible {
        return fail(world, Obligation::Progress, RULE);
    }
    if !rest {
        return fail(world, Obligation::Resources, HEALED_INEXACT);
    }
    mark(world, LATER_SETTLED);
    mark(world, "qualified exact read")
}

const SATURATED: [Step; 10] = replaced(
    replaced(H4_GET, "arm", step("arm", always, arm)),
    "peer-read",
    step("peer-read", peer_decided_or_late, peer_exact_beside_held),
);

const UNSATURATED: [Step; 10] = replaced(
    replaced(
        replaced(
            replaced(H4_GET, "arm", step("arm", always, unarmed)),
            "reads-held",
            step("reads-held", always, nothing_held),
        ),
        "peer-read",
        step("peer-read", peer_decided_or_late, peer_exact_unsaturated),
    ),
    "healed",
    step("healed", saturated_drained, unsaturated_exact),
);

const UNSATURATED_PEER_LATE: [Step; 10] = replaced(
    UNSATURATED,
    "peer-read",
    step(
        "peer-read-late",
        peer_decided_or_late,
        peer_unsaturated_late,
    ),
);

const UNSATURATED_FIRST_REFUSED: [Step; 10] = replaced(
    UNSATURATED,
    "healed",
    step(
        "healed-first-refused",
        saturated_drained,
        unsaturated_first_refused,
    ),
);

const UNSATURATED_PAST_MISSING: [Step; 10] = replaced(
    UNSATURATED,
    "healed",
    step(
        "healed-past-missing",
        saturated_drained,
        unsaturated_past_missing,
    ),
);

/// The falsifier releases both saturating reads before the other peer's GET.
fn drain_behind(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    for &token in &world.history.held {
        world.scene.control.release(token);
    }
    1
}

fn drained_and_active(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    device_drained(world, now) && active_put(world, now)
}

const DRAINED: [Step; 10] = replaced(
    replaced(
        SATURATED,
        "over-share",
        step("reads-drained", always, drain_behind),
    ),
    "peer-get",
    step("peer-get", drained_and_active, peer_get),
);

const SATURATED_WITNESSES: &[&str] = &[
    "share saturated",
    "saturating reads held",
    STILL_HELD,
    "eligible peer progressed",
    "charges stayed within the share",
    "qualified exact read",
];

const UNSATURATED_WITNESSES: &[&str] = &[
    NEVER_ARMED,
    NOTHING_HELD,
    "eligible peer progressed",
    LATER_SETTLED,
    "qualified exact read",
];

/// The marks a failure of the first history needs before it counts: the fault formed.
const PREMISE: &[&str] = &["share saturated", "saturating reads held"];

const UNSATURATED_JUDGED: &[Obligation] = &[Obligation::Progress, Obligation::Resources];

/// The obligation each mark of the siblings' healed steps judges.
pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (LATER_SETTLED, Obligation::Resources),
    (TRADERS_EXACT, Obligation::Resources),
];

const UNSATURATED_PREMISE: &[&str] = &[NEVER_ARMED, NOTHING_HELD];

const PAST_PREMISE: &[&str] = &[NEVER_ARMED, NOTHING_HELD, PAST_ISSUED];

pub(super) const SATURATED_SHARES: [History; 6] = [
    control(
        history(
            "ss1-get-beside-a-saturated-share",
            &SATURATED,
            SATURATED_WITNESSES,
            H4,
            Expect::Pass,
        ),
        PREMISE,
    ),
    history(
        "ss1-get-beside-an-open-share",
        &UNSATURATED,
        UNSATURATED_WITNESSES,
        UNSATURATED_JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "ss1-open-share-peer-late",
            &UNSATURATED_PEER_LATE,
            UNSATURATED_WITNESSES,
            UNSATURATED_JUDGED,
            Expect::Violation(Obligation::Progress, RULE),
        ),
        UNSATURATED_PREMISE,
    ),
    control(
        history(
            "ss1-open-share-get-read-as-refused",
            &UNSATURATED_FIRST_REFUSED,
            UNSATURATED_WITNESSES,
            UNSATURATED_JUDGED,
            Expect::Violation(Obligation::Progress, RULE),
        ),
        UNSATURATED_PREMISE,
    ),
    control(
        history(
            "ss1-get-beside-a-drained-share",
            &DRAINED,
            SATURATED_WITNESSES,
            H4,
            Expect::Unsuccessful(STILL_HELD),
        ),
        PREMISE,
    ),
    control(
        history(
            "ss1-open-share-get-past-read-as-missing",
            &UNSATURATED_PAST_MISSING,
            UNSATURATED_WITNESSES,
            UNSATURATED_JUDGED,
            Expect::Violation(Obligation::Resources, HEALED_INEXACT),
        ),
        PAST_PREMISE,
    ),
];

/// The GET client's first read is held at the device.
const FIRST_HELD: &str = "the GET client's first read held";
/// The peer's read waited, under its kept grant, for the read command the
/// GET client's read holds.
const PEER_WAITED: &str = "the peer's read waited for the command";
/// The sibling's peer's read took a free read command at once.
const PEER_SUBMITTED: &str = "the peer's read took a free command";
/// Each trade's released terminal and the GET client's next GET reached the
/// owner before its next turn, the owner refused none of the traded GETs,
/// and a trade ran within two paces of the peer's bound when the peer's GET
/// reached it.
const TRADED: &str = "a terminal met the next GET at the owner";

/// The client held a traded GET decided when the trades stopped.
const EXIT_DECIDED: &str = "a trader decided at the exit";

/// Every GET the GET client traded read the resident exactly.
const TRADERS_EXACT: &str = "each traded GET read exactly";

/// Microseconds between two trades.
const TRADE_US: u64 = 5_000;

/// Microseconds from the peer's issue after which the exit control waits
/// no longer for a decided traded GET: the peer's bound and four trade
/// paces more.
const EXIT_WAIT_US: u64 = BOUND_US + 4 * TRADE_US;

/// A GET of the resident object from the GET client.
fn trader_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> Option<RequestId> {
    let id = world.scene.clients[1]
        .get(key(1), 0, 1 << 20, now, super::super::WAIT_US)
        .ok()?;
    world.history.ids.push(id);
    Some(id)
}

fn first_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    trader_get(world, now).map_or(STAY, |_| 1)
}

fn mark_first_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, FIRST_HELD)
}

/// The peer's GET of the resident object, issued with the world's wait while
/// reads stay held. The volume's count of reads that waited is the baseline
/// of the next step.
fn waiting_peer_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let issued = peer_get_starved(world, now);
    world.history.kept = world.scene.owner.volume_report().reads_waited;
    issued
}

/// The owner started the peer's read: the read waited or the device holds
/// it beside the GET client's read, or the peer's GET was decided or late.
fn peer_read_started(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    world.scene.owner.volume_report().reads_waited > world.history.kept
        || world.history.held.len() >= 2
        || peer_decided_or_late(world, now)
}

/// The premise of the one-command share: the peer's read waited and the
/// device holds only the GET client's read.
fn peer_waited(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let waited = world.scene.owner.volume_report().reads_waited;
    peer_waited_counting(world, waited)
}

/// The falsifier forces the `PEER_WAITED` premise to fail.
fn peer_wait_uncounted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let unchanged = world.history.kept;
    peer_waited_counting(world, unchanged)
}

fn peer_waited_counting(world: &mut Mixed<'_, '_, '_>, reads_waited: u64) -> u64 {
    let waited = reads_waited == world.history.kept + 1;
    premised(world, waited && world.history.held.len() == 1, PEER_WAITED)
}

/// The sibling's premise: the peer's read waited for nothing and the device
/// holds both reads.
fn peer_submitted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let submitted = world.scene.owner.volume_report().reads_waited == world.history.kept;
    premised(
        world,
        submitted && world.history.held.len() == 2,
        PEER_SUBMITTED,
    )
}

/// The next trade is due: the peer's GET was decided or its bound passed,
/// or the pace's wake passed while the device holds a read, every GET of
/// the GET client but its latest was decided, and the owner charges that
/// client one request, so its share has room for the next GET.
fn trade_due(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    if peer_decided_or_late(world, now) {
        return true;
    }
    let client = &world.scene.clients[1];
    let ids = &world.history.ids;
    let older = &ids[..ids.len().saturating_sub(1)];
    let census = world.scene.owner.peer_census(PeerId(1));
    world.history.wake.is_none_or(|wake| now >= wake)
        && !world.history.held.is_empty()
        && older.iter().all(|&id| client.outcome(id).is_some())
        && census.active + census.draining == 1
}

/// Retires each GET of `ids` and judges it: the world's read check
/// (`handout_misread`) on the outcome the client observed and the bytes it
/// returned, as `alter` leaves them with the GET's index in `ids`; then the
/// outcome and bytes as `read` leaves them. A refusal there leaves the
/// premise TRADED unformed, and any other ending than `Complete` with the
/// resident's exact bytes fails HEALED_INEXACT. The step outcome of the
/// first GET that fails a check, which ends retirement there, or `None`
/// when every GET passed.
fn retire_traded(
    world: &mut Mixed<'_, '_, '_>,
    ids: Vec<RequestId>,
    alter: impl Fn(usize, &mut Vec<u8>),
    read: impl Fn(usize, Option<Outcome>, &mut Vec<u8>) -> Option<Outcome>,
) -> Option<u64> {
    for (at, id) in ids.into_iter().enumerate() {
        let mut bytes = drain(&mut world.scene.clients[1], id);
        alter(at, &mut bytes);
        let observed = world.collect_get(1, id);
        let _ = world.scene.clients[1].retire(id);
        if observed.is_some_and(|outcome| handout_misread(world, outcome, &bytes)) {
            return Some(0);
        }
        let outcome = read(at, observed, &mut bytes);
        if matches!(outcome, Some(Outcome::Pressure(_))) {
            return Some(premised(world, false, TRADED));
        }
        if outcome != Some(Outcome::Complete) || bytes != version_a() {
            return Some(fail(world, Obligation::Resources, HEALED_INEXACT));
        }
    }
    None
}

/// Retires and judges, as [`retire_traded`] does, each GET of the GET
/// client the client holds decided, and keeps the others for the healed
/// step. `alter` takes each decided GET's index in `history.ids` and its
/// returned bytes before the world's read check. `read` takes each GET's
/// index in `history.ids` and its outcome, `None` while undecided; an
/// undecided GET `read` gives as refused leaves TRADED unformed. The step
/// outcome of the first GET that fails a check, or `None` when every
/// decided GET passed.
fn retire_decided(
    world: &mut Mixed<'_, '_, '_>,
    alter: impl Fn(usize, &mut Vec<u8>),
    read: impl Fn(usize, Option<Outcome>) -> Option<Outcome>,
) -> Option<u64> {
    let mut kept = Vec::new();
    for (at, id) in std::mem::take(&mut world.history.ids)
        .into_iter()
        .enumerate()
    {
        if world.scene.clients[1].outcome(id).is_some() {
            let retired = retire_traded(
                world,
                vec![id],
                |_, bytes| alter(at, bytes),
                |_, outcome, _| read(at, outcome),
            );
            if retired.is_some() {
                return retired;
            }
        } else if matches!(read(at, None), Some(Outcome::Pressure(_))) {
            return Some(premised(world, false, TRADED));
        } else {
            kept.push(id);
        }
    }
    world.history.ids = kept;
    None
}

/// One trade, which repeats until the peer's GET is decided or its bound
/// passed. The GET client's decided GETs retire, each read exactly. The GET
/// client sends what it owes, then issues its next GET and sends it, so its
/// frame waits at the owner's end of the link, and the step then ends the
/// hold on every held read and posts each completion. No event runs inside
/// the step, so the owner's next turn applies the terminals and receives
/// the GET together: it frees the read command in `poll_terminals` and
/// admits the GET in `receive_batch`, both before the volume's tick. The
/// premise TRADED records that ordering from state each build has: a
/// further datagram was due at the owner's end of the link after the GET's
/// send, and no traded GET ended refused at the client. A refusal reaches
/// the client one link trip after the owner decides it, so the check reads
/// the refusals the client holds when each step runs. A trade that finds otherwise
/// ends the run unsuccessful under it. `send` false leaves the GET in the
/// client, the falsifier's trade. Once the peer's GET is decided or late,
/// the step trades no more. Trades that stopped more than two paces before
/// the peer's bound leave the device holding the command's read until that
/// bound, whichever read the volume gave the command to, so a peer's GET
/// that reached its bound after such a stop leaves TRADED unformed. After a
/// first trade the step then retires the decided GETs through
/// [`retire_decided`], with `alter` and `read` applied there to each GET's
/// index in `history.ids` with its bytes and its outcome, and ends.
fn trade_sending(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    send: bool,
    alter: impl Fn(usize, &mut Vec<u8>),
    read: impl Fn(usize, Option<Outcome>) -> Option<Outcome>,
) -> u64 {
    let traded = world.history.marks.contains(&TRADED);
    if peer_decided_or_late(world, now) {
        let bound = world.history.since + BOUND_US;
        let next = world.history.wake.take();
        if !traded {
            return 1;
        }
        if now >= bound && next.is_some_and(|next| next + TRADE_US < bound) {
            return premised(world, false, TRADED);
        }
        return retire_decided(world, alter, read).unwrap_or(1);
    }
    let latest = world.history.ids.len().saturating_sub(1);
    let older: Vec<_> = world.history.ids.drain(..latest).collect();
    if let Some(ended) = retire_traded(world, older, |_, _| (), |_, outcome, _| outcome) {
        return ended;
    }
    let _ = world.scene.clients[1].poll(now);
    let toward_owner = world.scene.nets[1].borrow().receivable(1);
    if trader_get(world, now).is_none() {
        return STAY;
    }
    if send {
        let _ = world.scene.clients[1].poll(now);
    }
    if world.scene.nets[1].borrow().receivable(1) <= toward_owner {
        return premised(world, false, TRADED);
    }
    for token in std::mem::take(&mut world.history.held) {
        world.scene.control.release(token);
        world.scene.control.post(token);
    }
    world.history.wake = Some(now + TRADE_US);
    if !traded {
        mark(world, TRADED);
    }
    STAY
}

/// The served history's step in the place of the trades: the device holds
/// no later read, and the step ends the hold on the GET client's read and
/// posts its completion. The GET client issues no further GET, so the
/// command the terminal frees has no taker other than the waiting read.
fn release_untraded(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_reads = false;
    for token in std::mem::take(&mut world.history.held) {
        world.scene.control.release(token);
        world.scene.control.post(token);
    }
    1
}

fn trade(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    trade_sending(world, now, true, |_, _| (), |_, outcome| outcome)
}

/// The stalled falsifier's trade is due as [`trade_due`] gives for the
/// first trade, and after it only once the peer's GET is decided or late.
fn stalled_trade_due(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    if world.history.marks.contains(&TRADED) {
        return peer_decided_or_late(world, now);
    }
    trade_due(world, now)
}

/// The falsifier's trade: the GET client never sends its next GET before
/// the release, so the premise TRADED fails at the first trade.
fn trade_unsent(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    trade_sending(world, now, false, |_, _| (), |_, outcome| outcome)
}

/// A falsifier: once the peer's GET is decided or late, the trade reads
/// the first traded GET the client still holds as refused.
fn trade_exit_refused(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    trade_sending(
        world,
        now,
        true,
        |_, _| (),
        |at, outcome| match at {
            0 => Some(Outcome::Pressure(Status::RequestPressure)),
            _ => outcome,
        },
    )
}

/// The index in `history.ids` of the first traded GET the client holds
/// decided.
fn first_decided(world: &Mixed<'_, '_, '_>) -> Option<usize> {
    let client = &world.scene.clients[1];
    let ids = &world.history.ids;
    ids.iter().position(|&id| client.outcome(id).is_some())
}

/// The trades stopped: a trade ran and the peer's GET is decided or late.
fn trades_stopped(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    peer_decided_or_late(world, now) && world.history.marks.contains(&TRADED)
}

/// The exit control's wait ended: `EXIT_WAIT_US` passed since the peer's
/// issue.
fn exit_waited(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now > world.history.since + EXIT_WAIT_US
}

/// The exit control's trade is due as [`trade_due`] gives until the trades
/// stop, and from then once the client holds a traded GET decided or the
/// wait ended: the GET the last trade released may still be undecided when
/// the trades stop.
fn exit_trade_due(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    if trades_stopped(world, now) {
        return first_decided(world).is_some() || exit_waited(world, now);
    }
    trade_due(world, now)
}

/// The falsifier's trade is due as [`trade_due`] gives until the trades
/// stop, and from then once the wait ended.
fn exit_trade_waited(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    if trades_stopped(world, now) {
        return exit_waited(world, now);
    }
    trade_due(world, now)
}

/// The exit control's trade: once the trades stopped, the step changes the
/// first byte of the traded GET `decided` gives, before the world's read
/// check. `decided` takes the index in `history.ids` of the first traded
/// GET the client holds decided. The premise EXIT_DECIDED forms when
/// `decided` gives one, and a run where it gives none ends unsuccessful
/// under it.
fn trade_exit_altering(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    decided: impl Fn(Option<usize>) -> Option<usize>,
) -> u64 {
    let decided = decided(first_decided(world));
    if trades_stopped(world, now) && premised(world, decided.is_some(), EXIT_DECIDED) == 0 {
        return 0;
    }
    trade_sending(
        world,
        now,
        true,
        |at, bytes| {
            if Some(at) == decided {
                flip_first(bytes);
            }
        },
        |_, outcome| outcome,
    )
}

/// A control: once the trades stopped and the client holds a traded GET
/// decided, the step changes the first byte of the first such GET, which
/// the world's read check fails under `Obligation::Bytes` ahead of the
/// peer's verdict.
fn trade_exit_corrupted(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    trade_exit_altering(world, now, |decided| decided)
}

/// The falsifier of EXIT_DECIDED: once the wait ended, the exit control's
/// trade reads every traded GET as undecided, so the premise fails.
fn trade_exit_undecided(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    trade_exit_altering(world, now, |_| None)
}

/// SS2's judge of the peer's GET as observed at `decided_at`, with its
/// bytes as `alter` leaves them. The GET client's GETs decided by then
/// retire first through [`retire_decided`], so a trader's failure of the
/// world's read check or of its exact bytes comes before the peer's
/// verdict.
fn traded_peer_read_at(
    world: &mut Mixed<'_, '_, '_>,
    decided_at: u64,
    alter: impl FnOnce(&mut Vec<u8>),
) -> u64 {
    if let Some(ended) = retire_decided(world, |_, _| (), |_, outcome| outcome) {
        return ended;
    }
    peer_read_judged(world, decided_at, alter)
}

fn traded_peer_read(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    traded_peer_read_at(world, now, |_| ())
}

fn traded_peer_read_late(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    traded_peer_read_at(world, now + 2 * BOUND_US, |_| ())
}

/// A control: the judge changes the first byte the peer's GET returned
/// before the world's read check, so a timely `Complete` fails that check
/// under `Obligation::Bytes`.
fn traded_peer_read_altered(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    traded_peer_read_at(world, now, |bytes| flip_first(bytes))
}

/// A control: the judge reads the peer's GET two bounds late and changes
/// its first byte, so the world's read check fails it under
/// `Obligation::Bytes` ahead of the bound.
fn traded_peer_read_late_altered(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    traded_peer_read_at(world, now + 2 * BOUND_US, |bytes| flip_first(bytes))
}

/// Each GET the GET client still holds reads the resident exactly once
/// healed, as [`retire_traded`] judges it through `alter` and `read`.
fn traders_judged(
    world: &mut Mixed<'_, '_, '_>,
    alter: impl Fn(usize, &mut Vec<u8>),
    read: impl Fn(usize, Option<Outcome>, &mut Vec<u8>) -> Option<Outcome>,
) -> u64 {
    let ids = std::mem::take(&mut world.history.ids);
    if let Some(ended) = retire_traded(world, ids, alter, read) {
        return ended;
    }
    mark(world, TRADERS_EXACT);
    mark(world, "qualified exact read")
}

fn traders_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    traders_judged(world, |_, _| (), |_, outcome, _| outcome)
}

/// A falsifier: the healed step reads the first GET it judges as refused.
fn traders_first_refused(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    traders_judged(
        world,
        |_, _| (),
        |at, outcome, _| match at {
            0 => Some(Outcome::Pressure(Status::RequestPressure)),
            _ => outcome,
        },
    )
}

/// A control: the healed step reads the first GET it judges as `Missing`.
fn traders_first_missing(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    traders_judged(
        world,
        |_, _| (),
        |at, outcome, _| match at {
            0 => Some(Outcome::Missing),
            _ => outcome,
        },
    )
}

/// A control: after the world's read check passes the first GET the healed
/// step judges, the step changes that GET's first byte.
fn traders_first_altered(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    traders_judged(
        world,
        |_, _| (),
        |at, outcome, bytes| {
            if at == 0 {
                flip_first(bytes);
            }
            outcome
        },
    )
}

/// A control: the healed step changes the first byte of the first GET it
/// judges before the world's read check, which fails it under
/// `Obligation::Bytes`.
fn traders_first_corrupted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    traders_judged(
        world,
        |at, bytes| {
            if at == 0 {
                flip_first(bytes);
            }
        },
        |_, outcome, _| outcome,
    )
}

/// The falsifier of PEER_WAITED's held count: the step judges the
/// volume's count of reads that waited as risen by one, so only the
/// device's two held reads fail the premise.
fn peer_wait_counted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let risen = world.history.kept + 1;
    peer_waited_counting(world, risen)
}

const WAITING: [Step; 10] = [
    step("arm", always, super::pressured_gets::arm_reads),
    step("first-get", active_get, first_get),
    step("first-read-held", read_held, mark_first_held),
    step("peer-get", active_put, waiting_peer_get),
    step("peer-read-waited", peer_read_started, peer_waited),
    step("trade", trade_due, trade),
    step("peer-read", always, traded_peer_read),
    step("release", always, release_everything),
    step("healed", saturated_drained, traders_exact),
    JUDGE,
];

const WAITING_UNTRADED: [Step; 10] = replaced(
    replaced(
        WAITING,
        "trade",
        step("release-untraded", always, release_untraded),
    ),
    "peer-read",
    step("peer-read", peer_decided_or_late, traded_peer_read),
);

const WAITING_UNSENT: [Step; 10] = replaced(
    WAITING,
    "trade",
    step("trade-unsent", trade_due, trade_unsent),
);

const WAITING_STALLED: [Step; 10] = replaced(
    WAITING,
    "trade",
    step("trade-stalled", stalled_trade_due, trade),
);

const WAITING_EXIT_REFUSED: [Step; 10] = replaced(
    WAITING,
    "trade",
    step("trade-exit-refused", trade_due, trade_exit_refused),
);

const WAITING_EXIT_CORRUPTED: [Step; 10] = replaced(
    WAITING,
    "trade",
    step("trade-exit-corrupted", exit_trade_due, trade_exit_corrupted),
);

const WAITING_EXIT_UNDECIDED: [Step; 10] = replaced(
    WAITING,
    "trade",
    step(
        "trade-exit-undecided",
        exit_trade_waited,
        trade_exit_undecided,
    ),
);

const WAITING_UNCOUNTED: [Step; 10] = replaced(
    WAITING,
    "peer-read-waited",
    step(
        "peer-read-uncounted",
        peer_read_started,
        peer_wait_uncounted,
    ),
);

const WAITING_COUNTED: [Step; 10] = replaced(
    WAITING,
    "peer-read-waited",
    step("peer-read-counted", peer_read_started, peer_wait_counted),
);

const BESIDE: [Step; 10] = replaced(
    WAITING,
    "peer-read-waited",
    step("peer-read-submitted", peer_read_started, peer_submitted),
);

const BESIDE_PEER_LATE: [Step; 10] = replaced(
    BESIDE,
    "peer-read",
    step("peer-read-late", always, traded_peer_read_late),
);

const BESIDE_PEER_ALTERED: [Step; 10] = replaced(
    BESIDE,
    "peer-read",
    step("peer-read-altered", always, traded_peer_read_altered),
);

const BESIDE_PEER_LATE_ALTERED: [Step; 10] = replaced(
    BESIDE,
    "peer-read",
    step(
        "peer-read-late-altered",
        always,
        traded_peer_read_late_altered,
    ),
);

const BESIDE_TRADER_CORRUPTED: [Step; 10] = replaced(
    BESIDE,
    "healed",
    step(
        "healed-first-corrupted",
        saturated_drained,
        traders_first_corrupted,
    ),
);

const BESIDE_TRADER_MISSING: [Step; 10] = replaced(
    BESIDE,
    "healed",
    step(
        "healed-first-missing",
        saturated_drained,
        traders_first_missing,
    ),
);

const BESIDE_TRADER_ALTERED: [Step; 10] = replaced(
    BESIDE,
    "healed",
    step(
        "healed-first-altered",
        saturated_drained,
        traders_first_altered,
    ),
);

const BESIDE_TRADER_REFUSED: [Step; 10] = replaced(
    BESIDE,
    "healed",
    step(
        "healed-first-refused",
        saturated_drained,
        traders_first_refused,
    ),
);

const WAITING_WITNESSES: &[&str] = &[
    FIRST_HELD,
    PEER_WAITED,
    TRADED,
    "eligible peer progressed",
    TRADERS_EXACT,
    "qualified exact read",
];

const BESIDE_WITNESSES: &[&str] = &[
    FIRST_HELD,
    PEER_SUBMITTED,
    TRADED,
    "eligible peer progressed",
    TRADERS_EXACT,
    "qualified exact read",
];

/// The served history trades nothing, so it marks no TRADED.
const UNTRADED_WITNESSES: &[&str] = &[
    FIRST_HELD,
    PEER_WAITED,
    "eligible peer progressed",
    TRADERS_EXACT,
    "qualified exact read",
];

const WAITING_PREMISE: &[&str] = &[FIRST_HELD, PEER_WAITED, TRADED];

const BESIDE_PREMISE: &[&str] = &[FIRST_HELD, PEER_SUBMITTED, TRADED];

const WAITING_EXIT_PREMISE: &[&str] = &[FIRST_HELD, PEER_WAITED, TRADED, EXIT_DECIDED];

/// The obligations of a control that changes a returned byte before the
/// world's read check: the family's, and that check's.
const ALTERED_JUDGED: &[Obligation] = &[
    Obligation::Progress,
    Obligation::Resources,
    Obligation::Bytes,
];

/// An SS2 history: its script issues every GET, so the world issues none
/// of its own.
const fn trading(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    expect: Expect,
) -> History {
    getting(
        history(name, script, witnesses, UNSATURATED_JUDGED, expect),
        [0, 0],
    )
}

/// SS2: the peer's read waits for the one read command while the GET
/// client's reads trade it, its sibling over three read commands, the
/// waiting read served once the command frees untraded, the controls of the
/// checks, and the falsifiers of the premises.
pub(super) const WAITING_READS: [History; 19] = [
    one_read_command(control(
        trading(
            "ss2-peer-read-waits-for-one-command",
            &WAITING,
            WAITING_WITNESSES,
            Expect::Violation(Obligation::Progress, RULE),
        ),
        WAITING_PREMISE,
    )),
    trading(
        "ss2-peer-read-beside-three-commands",
        &BESIDE,
        BESIDE_WITNESSES,
        Expect::Pass,
    ),
    control(
        trading(
            "ss2-three-commands-peer-late",
            &BESIDE_PEER_LATE,
            BESIDE_WITNESSES,
            Expect::Violation(Obligation::Progress, RULE),
        ),
        BESIDE_PREMISE,
    ),
    control(
        trading(
            "ss2-three-commands-trader-read-as-missing",
            &BESIDE_TRADER_MISSING,
            BESIDE_WITNESSES,
            Expect::Violation(Obligation::Resources, HEALED_INEXACT),
        ),
        BESIDE_PREMISE,
    ),
    control(
        trading(
            "ss2-peer-read-submitted-as-waiting",
            &WAITING,
            WAITING_WITNESSES,
            Expect::Unsuccessful(PEER_WAITED),
        ),
        WAITING_PREMISE,
    ),
    control(
        trading(
            "ss2-three-commands-trader-read-as-refused",
            &BESIDE_TRADER_REFUSED,
            BESIDE_WITNESSES,
            Expect::Unsuccessful(TRADED),
        ),
        BESIDE_PREMISE,
    ),
    one_read_command(control(
        trading(
            "ss2-one-command-trade-unsent",
            &WAITING_UNSENT,
            WAITING_WITNESSES,
            Expect::Unsuccessful(TRADED),
        ),
        WAITING_PREMISE,
    )),
    control(
        trading(
            "ss2-three-commands-trader-read-altered",
            &BESIDE_TRADER_ALTERED,
            BESIDE_WITNESSES,
            Expect::Violation(Obligation::Resources, HEALED_INEXACT),
        ),
        BESIDE_PREMISE,
    ),
    one_read_command(control(
        trading(
            "ss2-one-command-trader-read-as-refused-at-exit",
            &WAITING_EXIT_REFUSED,
            WAITING_WITNESSES,
            Expect::Unsuccessful(TRADED),
        ),
        WAITING_PREMISE,
    )),
    one_read_command(control(
        trading(
            "ss2-one-command-peer-wait-read-as-uncounted",
            &WAITING_UNCOUNTED,
            WAITING_WITNESSES,
            Expect::Unsuccessful(PEER_WAITED),
        ),
        WAITING_PREMISE,
    )),
    control(
        History {
            obligations: ALTERED_JUDGED,
            ..trading(
                "ss2-three-commands-peer-read-altered",
                &BESIDE_PEER_ALTERED,
                BESIDE_WITNESSES,
                Expect::Violation(Obligation::Bytes, COMPLETE_MISREAD),
            )
        },
        BESIDE_PREMISE,
    ),
    control(
        History {
            obligations: ALTERED_JUDGED,
            ..trading(
                "ss2-three-commands-peer-late-read-altered",
                &BESIDE_PEER_LATE_ALTERED,
                BESIDE_WITNESSES,
                Expect::Violation(Obligation::Bytes, COMPLETE_MISREAD),
            )
        },
        BESIDE_PREMISE,
    ),
    control(
        History {
            obligations: ALTERED_JUDGED,
            ..trading(
                "ss2-three-commands-trader-read-corrupted",
                &BESIDE_TRADER_CORRUPTED,
                BESIDE_WITNESSES,
                Expect::Violation(Obligation::Bytes, COMPLETE_MISREAD),
            )
        },
        BESIDE_PREMISE,
    ),
    one_read_command(control(
        trading(
            "ss2-one-command-peer-read-as-submitted",
            &BESIDE,
            BESIDE_WITNESSES,
            Expect::Unsuccessful(PEER_SUBMITTED),
        ),
        BESIDE_PREMISE,
    )),
    control(
        trading(
            "ss2-three-commands-peer-wait-read-as-counted",
            &WAITING_COUNTED,
            WAITING_WITNESSES,
            Expect::Unsuccessful(PEER_WAITED),
        ),
        WAITING_PREMISE,
    ),
    one_read_command(control(
        History {
            obligations: ALTERED_JUDGED,
            ..trading(
                "ss2-one-command-trader-read-corrupted-at-exit",
                &WAITING_EXIT_CORRUPTED,
                WAITING_WITNESSES,
                Expect::Violation(Obligation::Bytes, COMPLETE_MISREAD),
            )
        },
        WAITING_EXIT_PREMISE,
    )),
    one_read_command(control(
        trading(
            "ss2-one-command-trader-read-as-undecided-at-exit",
            &WAITING_EXIT_UNDECIDED,
            WAITING_WITNESSES,
            Expect::Unsuccessful(EXIT_DECIDED),
        ),
        WAITING_EXIT_PREMISE,
    )),
    one_read_command(control(
        trading(
            "ss2-one-command-trades-stalled",
            &WAITING_STALLED,
            WAITING_WITNESSES,
            Expect::Unsuccessful(TRADED),
        ),
        WAITING_PREMISE,
    )),
    one_read_command(trading(
        "ss2-one-command-peer-read-served-untraded",
        &WAITING_UNTRADED,
        UNTRADED_WITNESSES,
        Expect::Pass,
    )),
];

#[cfg(test)]
mod tests {
    use super::super::tests::{ROOTS, ends_as_declared_at, first_failure, recorded};
    use super::super::{Expect, History};
    use super::{PEER_WAITED, TRADED, WAITING_READS};

    /// A bundle that ends unsuccessful meets its own falsifier's declaration
    /// and fails the declaration of the other premise's falsifier: the
    /// recorded witness tells PEER_WAITED from TRADED.
    #[test]
    fn an_unsuccessful_bundle_ends_as_declared_only_under_its_witness() {
        let by = |name| WAITING_READS.iter().find(|h| h.name == name).expect(name);
        for (name, other) in [
            ("ss2-peer-read-submitted-as-waiting", TRADED),
            ("ss2-one-command-trade-unsent", PEER_WAITED),
        ] {
            let history = by(name);
            let (_, loaded) = recorded(name, ROOTS[0]);
            assert_eq!(history.ends_as_declared(&loaded), Ok(()), "{name}");
            let swapped = History {
                expect: Expect::Unsuccessful(other),
                ..*history
            };
            assert!(swapped.ends_as_declared(&loaded).is_err(), "{name}");
        }
    }

    /// A record that holds the 41-byte cut of a longer witness ends as no
    /// declaration: a declaration of the cut itself or of the longer text
    /// is refused, and so is one whose 41st byte falls inside a character,
    /// without a panic.
    #[test]
    fn a_cut_witness_record_ends_as_no_declaration() {
        use super::super::super::bundle::{OBSERVED, unsuccessful_rule};
        const LONG: &str = "the peer's read waited for the command and the trade ran past it";
        const STRADDLE: &str = "the peer's read waited for the command .\u{e9}";
        let cut = crate::sim::trace::PAYLOAD - 3;
        let name = "ss2-peer-read-submitted-as-waiting";
        let history = WAITING_READS.iter().find(|h| h.name == name).expect(name);
        let (_, mut loaded) = recorded(name, ROOTS[0]);
        let event = loaded
            .events
            .iter_mut()
            .find(|event| event.kind == OBSERVED && event.payload[2] as usize == PEER_WAITED.len())
            .expect("the recorded witness");
        event.payload[2] = cut as u8;
        event.payload[3..3 + cut].copy_from_slice(&LONG.as_bytes()[..cut]);
        assert_eq!(unsuccessful_rule(&loaded).as_deref(), Some(&LONG[..cut]));
        assert_eq!(STRADDLE.len(), cut + 1);
        for witness in [&LONG[..cut], LONG, STRADDLE] {
            let declared = History {
                expect: Expect::Unsuccessful(witness),
                ..*history
            };
            assert!(declared.ends_as_declared(&loaded).is_err(), "{witness}");
        }
    }

    /// Each SS2 history ends as it declares under the sibling families'
    /// pinned roots, with the declared witness of an unsuccessful ending,
    /// and its bundle replays equal.
    #[test]
    fn the_waiting_read_family_ends_as_declared_under_pinned_roots() {
        for history in &WAITING_READS {
            for root in ROOTS {
                assert_eq!(
                    first_failure(history.name, root),
                    history.expect.failure(),
                    "{} at {root}",
                    history.name
                );
                ends_as_declared_at(history, root);
            }
        }
    }
}
