//! Refused-GET histories: a GET the owner refuses for request pressure
//! settles its wire identity, so a retransmission that arrives once the
//! pressure cleared replays the refusal and starts no read the refused
//! client never drives.
//!
//! Property: the rule "a settled GET's row held an admitted request" of
//! `narrate/rules.rs`, which the histories `i7-get-refused-readmitted` and
//! `i7-get-refused-prompt` of `histories/incidents.rs` judge.
//!
//! Second property: the refusal settles the identity (`net/serve.rs`, the
//! GET pressure refusals; `net/namespace.rs`, `Namespace::settle`). The step
//! `row` raises "a refused GET's wire identity stayed unsettled" when the
//! slot's watermark is unset or below the refused generation.
//!
//! Both histories run the single-owner world, in which a peer's share is
//! two requests. Client 1 is the peer that reads. Key 1 holds the resident
//! object.
//!
//! - `rf1-get-refused-then-retransmitted`: the device holds reads, and the
//!   client issues two GETs of key 1 that fill its share. It then issues a
//!   third GET on a free wire slot, and the link delays an ERROR of the
//!   third GET's identity toward the client by 300 link turns and a START of
//!   it by 600, so the client retransmits the GET before it learns of the
//!   refusal. The held reads are then released. The step `room` runs when
//!   the owner first charges the client less than its share and keeps the
//!   link's count of the third GET's ERRORs at that moment. Once the client
//!   decided the third GET, the premise `REFUSED` forms when the outcome is
//!   `Pressure(RequestPressure)` and the premise `RESENT` when the client
//!   had sent a GET again since the issue, and the client retires the
//!   request. After `QUIET_US` more, past the delayed START's arrival and
//!   the client's last retransmission, the step `row` reads the owner's wire
//!   slot of the refused identity. It fails with the rule when the slot's
//!   watermark is the refused generation and the slot binds a request.
//!   Otherwise the premise `REPLAYED` forms when the owner replayed an
//!   outcome after the share had room, which is its answer to a
//!   retransmission that arrived after the pressure cleared, and the premise
//!   `UNBOUND` when the slot binds no request.
//! - `rf1-get-refused-promptly`: the same steps, but the link delays
//!   nothing, so the refusal reaches the client before its first
//!   retransmission. In the place of `RESENT` the premise `ONCE` forms when
//!   the client had sent no GET again between the issue and the decision,
//!   and in the place of `REPLAYED` nothing: the step `row` requires
//!   `UNBOUND` alone.
//!
//! The world issues the plan's own GETs for the same client during both
//! histories. The link rules name the third GET's identity alone, so the
//! link delays no answer to those GETs in either history.
//!
//! A premise that does not form ends the run unsuccessful under its name.
//!
//! `rf1-get-refused-judged-as-readmitted` is a control: the first history's
//! steps, with the slot handed to the judgment as an owner that admitted the
//! retransmission would leave it, bound to a request at the refused
//! generation. It fails with the rule.
//!
//! In the control `rf1-get-refused-judged-unsettled`, the second history's
//! step `row` receives the slot with its watermark one generation below the
//! refused one and `slot.active == None`, and raises "a refused GET's wire
//! identity stayed unsettled".

use super::super::super::frame::Kind;
use super::super::super::namespace::WireSlot;
use super::super::super::rules::{Chain, Effect, MANIFEST, Rule, Selector};
use super::super::super::served;
use super::super::{OWNER, WAIT_US};
use super::*;

/// The rule both histories judge.
const ADMITTED: &str = "a settled GET's row held an admitted request";

/// An unset `slot.watermark` or one below the refused GET's generation marks its wire identity as
/// unsettled.
const UNSETTLED: &str = "a refused GET's wire identity stayed unsettled";

const HELD: &str = "reads held";
const DELAYED: &str = "a GET past the share issued, its refusal and START delayed";
const PROMPT: &str = "a GET past the share issued, its refusal prompt";
const ROOM: &str = "the share had room again";
const REFUSED: &str = "the GET past the share was refused typed";
const RETIRED: &str = "the client retired the settled request";
const REPLAYED: &str = "the owner replayed the refusal after the share had room";
const RESENT: &str = "the client retransmitted before the refusal reached it";
const ONCE: &str = "the refusal reached the client before any retransmission";
const UNBOUND: &str = "the settled GET's slot binds no request";

/// The client that reads, and its link.
const READER: usize = 1;

/// The reading client as the owner names it.
const PEER: PeerId = PeerId(1);

/// The link end of a client.
const CLIENT_END: usize = 0;

/// Link turns the first history delays the refusal's ERROR: past the client's first retransmissions.
const ERROR_TURNS: u64 = 300;

/// Link turns the first history delays a START of the refused identity: past the delayed ERROR.
const START_TURNS: u64 = 600;

/// Microseconds after the client settled before the identity's slot is judged: past the delayed
/// START's arrival and the client's last retransmission, and inside the GET's wait.
const QUIET_US: u64 = 80_000;
const _: () = assert!(QUIET_US < WAIT_US);

/// The live requests the owner charges to the reading client's share.
fn charged(world: &Mixed<'_, '_, '_>) -> u32 {
    let census = world.scene.owner.peer_census(PEER);
    census.active + census.draining
}

/// The GET frames the reading client sent again so far.
fn retransmitted(world: &Mixed<'_, '_, '_>) -> u64 {
    world.scene.clients[READER].fetch_report().get_retries
}

fn hold_reads(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_reads = true;
    mark(world, HELD)
}

/// The owner charges the client its whole share, and the device holds both reads.
fn share_held(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.owner.peer_census(PEER).active >= OWNER.peer_requests
        && world.history.held.len() >= OWNER.peer_requests as usize
}

/// The client's GET past its full share. `rules` act on the client's link from here on.
fn third_get(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    rules: fn(u64) -> Vec<Rule>,
    witness: &'static str,
) -> u64 {
    let Ok(id) = world.scene.clients[READER].get(key(1), 0, 1 << 20, now, WAIT_US) else {
        return STAY;
    };
    let wire = world.scene.clients[READER]
        .get_wire(id)
        .expect("a live GET names its wire");
    world.history.attempts.push((READER, id, wire));
    world.history.peer = Some(id);
    world.history.since = now;
    world.history.sent = retransmitted(world);
    let rules = rules(wire);
    let taps = [rules.len()];
    let chain = Chain::new(rules, &taps, &MANIFEST).expect("a bounded chain");
    world.scene.nets[READER].borrow_mut().set_rules(chain);
    mark(world, witness)
}

/// The first history's fault: the refusal reaches the client after its GET retransmissions, and a START
/// those retransmissions earn after the refusal.
fn late_answers(wire: u64) -> Vec<Rule> {
    let error = Selector::All(vec![
        Selector::Kind(Kind::Error),
        Selector::Request(wire),
        Selector::Toward(CLIENT_END),
    ]);
    let start = Selector::All(vec![
        Selector::Kind(Kind::Start),
        Selector::Request(wire),
        Selector::Toward(CLIENT_END),
    ]);
    vec![
        Rule::new(error, Effect::Delay(ERROR_TURNS)),
        Rule::new(start, Effect::Delay(START_TURNS)),
    ]
}

fn no_rules(_: u64) -> Vec<Rule> {
    Vec::new()
}

fn third_get_delayed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    third_get(world, now, late_answers, DELAYED)
}

fn third_get_prompt(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    third_get(world, now, no_rules, PROMPT)
}

/// The owner charges the client less than its share.
fn share_room(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    charged(world) < OWNER.peer_requests
}

/// A delayed ERROR contributes to the count at capture time, before delivery.
fn refusals_sent(world: &Mixed<'_, '_, '_>) -> u64 {
    let net = world.scene.nets[READER].borrow();
    let sent = net.rules().captures().iter().filter(|capture| {
        capture.kind == Some(Kind::Error) && capture.decision.delay == Some(ERROR_TURNS)
    });
    sent.count() as u64
}

/// The count at `ROOM` serves as the baseline for `replayed` in `judge_row`.
fn note_room(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.carried = refusals_sent(world);
    mark(world, ROOM)
}

fn third_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .peer
        .is_some_and(|id| world.scene.clients[READER].outcome(id).is_some())
}

/// The premise REFUSED: the client's third GET ended `Pressure(RequestPressure)`. With `resent` the
/// client must have sent a GET again since it issued the third one, and without it must not have. The
/// client retires the request, and the history waits `QUIET_US`.
fn third_refused(world: &mut Mixed<'_, '_, '_>, now: u64, resent: bool) -> u64 {
    let Some(id) = world.history.peer else {
        return premised(world, false, REFUSED);
    };
    let outcome = world.collect_get(READER, id);
    let again = retransmitted(world) > world.history.sent;
    let _ = world.scene.clients[READER].retire(id);
    world.history.deadline = now + QUIET_US;
    world.history.wake = Some(world.history.deadline + 1);
    let typed = outcome == Some(Outcome::Pressure(Status::RequestPressure));
    if premised(world, typed, REFUSED) == 0 {
        return 0;
    }
    if resent {
        premised(world, again, RESENT)
    } else {
        premised(world, !again, ONCE)
    }
}

fn third_refused_late(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    third_refused(world, now, true)
}

fn third_refused_promptly(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    third_refused(world, now, false)
}

fn quiet(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now > world.history.deadline
}

/// The owner's record of one wire slot.
type Slot = WireSlot<served::Outcome>;

/// Returns the refused GET's wire identity and owner slot. The history must name the request, and the
/// client must have retired it.
fn settled_slot(world: &mut Mixed<'_, '_, '_>) -> Option<(RequestId, Slot)> {
    let Some(id) = world.history.peer.take() else {
        premised(world, false, REFUSED);
        return None;
    };
    let wire = kept_wire(world, READER, id).map(RequestId::from_wire);
    let held = world.scene.clients[READER].get_wire(id).is_some();
    let Some(wire) = wire.filter(|_| !held) else {
        premised(world, false, RETIRED);
        return None;
    };
    let slot = world
        .scene
        .owner
        .request_slot(PEER, wire.slot())
        .unwrap_or_default();
    Some((wire, slot))
}

/// The judgment: `slot`, the owner's wire slot of the refused identity `wire`, binds no request at the
/// refused generation, and its watermark has reached that generation. With `resent`, the `REPLAYED`
/// premise requires the count of ERROR captures delayed by `ERROR_TURNS` to exceed its `ROOM` baseline.
fn judge_row(world: &mut Mixed<'_, '_, '_>, wire: RequestId, slot: &Slot, resent: bool) -> u64 {
    if slot.watermark == Some(wire.generation()) && slot.active.is_some() {
        return fail(world, Obligation::Resources, ADMITTED);
    }
    if slot
        .watermark
        .is_none_or(|settled| settled < wire.generation())
    {
        return fail(world, Obligation::Resources, UNSETTLED);
    }
    let replayed = refusals_sent(world) > world.history.carried;
    if resent && premised(world, replayed, REPLAYED) == 0 {
        return 0;
    }
    premised(world, slot.active.is_none(), UNBOUND)
}

fn row_after_retransmission(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some((wire, slot)) = settled_slot(world) else {
        return 0;
    };
    judge_row(world, wire, &slot, true)
}

fn row_after_prompt_refusal(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some((wire, slot)) = settled_slot(world) else {
        return 0;
    };
    judge_row(world, wire, &slot, false)
}

/// The slot `judge_row` receives has its watermark one generation below the refused one, or unset
/// for generation zero, and `active == None`.
fn row_unsettled(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some((wire, slot)) = settled_slot(world) else {
        return 0;
    };
    let unsettled = Slot {
        watermark: wire.generation().checked_sub(1),
        active: None,
        ..slot
    };
    judge_row(world, wire, &unsettled, false)
}

/// A control: the slot is judged bound to a request at the refused generation, as an owner that
/// admitted the retransmission once its share had room would leave it.
fn row_readmitted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some((wire, slot)) = settled_slot(world) else {
        return 0;
    };
    let bound = Slot {
        watermark: Some(wire.generation()),
        active: Some(wire),
        ..slot
    };
    judge_row(world, wire, &bound, true)
}

const READMITTED: [Step; 8] = [
    step("hold-reads", always, hold_reads),
    step("saturate", active_get, saturate),
    step("third-get", share_held, third_get_delayed),
    step("release-reads", always, release_reads),
    step("room", share_room, note_room),
    step("third-refused", third_decided, third_refused_late),
    step("row", quiet, row_after_retransmission),
    JUDGE,
];

const PROMPTLY: [Step; 8] = replaced(
    replaced(
        replaced(
            READMITTED,
            "third-get",
            step("third-get", share_held, third_get_prompt),
        ),
        "third-refused",
        step("third-refused", third_decided, third_refused_promptly),
    ),
    "row",
    step("row", quiet, row_after_prompt_refusal),
);

const JUDGED_AS_READMITTED: [Step; 8] = replaced(
    READMITTED,
    "row",
    step("row-readmitted", quiet, row_readmitted),
);

const JUDGED_UNSETTLED: [Step; 8] =
    replaced(PROMPTLY, "row", step("row-unsettled", quiet, row_unsettled));

const READMITTED_WITNESSES: &[&str] = &[
    HELD,
    "share saturated",
    DELAYED,
    ROOM,
    REFUSED,
    RESENT,
    REPLAYED,
    UNBOUND,
];

const PROMPTLY_WITNESSES: &[&str] = &[
    HELD,
    "share saturated",
    PROMPT,
    ROOM,
    REFUSED,
    ONCE,
    UNBOUND,
];

const JUDGED: &[Obligation] = &[Obligation::Resources];

/// The obligation the last mark of the step `row` judges: the step records it only after the rule's
/// check of the slot passed.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(UNBOUND, Obligation::Resources)];

pub(super) const REFUSED_GETS: [History; 4] = [
    getting(
        history(
            "rf1-get-refused-then-retransmitted",
            &READMITTED,
            READMITTED_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        [0, 3],
    ),
    getting(
        history(
            "rf1-get-refused-promptly",
            &PROMPTLY,
            PROMPTLY_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        [0, 3],
    ),
    control(
        getting(
            history(
                "rf1-get-refused-judged-as-readmitted",
                &JUDGED_AS_READMITTED,
                READMITTED_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::Resources, ADMITTED),
            ),
            [0, 3],
        ),
        &[REFUSED, RESENT],
    ),
    control(
        getting(
            history(
                "rf1-get-refused-judged-unsettled",
                &JUDGED_UNSETTLED,
                PROMPTLY_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::Resources, UNSETTLED),
            ),
            [0, 3],
        ),
        &[REFUSED, ONCE],
    ),
];
