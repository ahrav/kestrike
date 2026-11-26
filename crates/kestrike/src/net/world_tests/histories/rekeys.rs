//! Rekey histories: each client's GET issued at an applied rekey settles
//! within the request's wait plus one owner maintenance rest.
//!
//! Property: the rule "a healed request stalled past its bound" of
//! `narrate/rules.rs`, which `World::watch_episodes` raises for the
//! generated profiles. Each witnessed held-update delivery opens an episode
//! per client it affects, which a GET that client issues afterward must
//! settle within `EPISODE_TURNS` turns and `EPISODE_US` of the delivery. The
//! time bound is the deadline of the GET that settles it, `WAIT_US`, plus one
//! owner maintenance rest.
//!
//! In a scripted history the step `settled` raises "a healed request stalled
//! past its bound" when the turn count exceeds `EPISODE_TURNS` or the elapsed
//! time exceeds `EPISODE_US`. `Episode::stalled` checks the same bounds.
//!
//! Both histories wait until each client holds an active session, run the
//! step `rekey`, and in the next step issue one GET of the resident object
//! from each client with wait `WAIT_US`. The world advances its clock only
//! when nothing is runnable, so that step runs at the time `rekey` ran; the
//! premise `ISSUED` requires it. The step `settled` runs once each client
//! decided its GET or the run passed the time bound or the turn bound; a wake
//! one microsecond past the time bound lets the clock cross that bound.
//! `settled` raises the rule when it runs past either bound: a GET is then
//! undecided, or was first seen decided past the bound.
//!
//! - `rk1-get-after-a-rekey`: `rekey` applies a rekey at the owner as
//!   `World::deliver` does, with the next key epoch and a nonce drawn from
//!   the run's chooser. The premise `REKEYED` forms when the owner's key
//!   epoch rose by one. The owner then holds new keys and no session, no
//!   reply reaches a client, and each client's own deadline ends its GET.
//!   Inside the bound, the step `outcomes` requires what `Episode::healed`
//!   requires of an applied rekey: each GET ended neither `Complete` nor
//!   `Incomplete` and delivered no byte.
//! - `rk1-get-with-keys-kept`: `rekey` leaves the keys alone, and the
//!   premise `KEPT` requires the key epoch unchanged at the GETs' issue.
//!   Each GET then completes with the object's exact bytes inside the same
//!   bound.
//!
//! In the control `rk1-get-after-a-rekey-judged-late`, `settled` raises "a
//! healed request stalled past its bound" for an elapsed time one
//! microsecond past `EPISODE_US`. In
//! `rk1-get-after-a-rekey-judged-past-its-turns`, `settled` raises it for a
//! turn count of `EPISODE_TURNS + 1`.
//! `rk1-get-with-keys-kept-judged-as-rekeyed`
//! holds the counterpart's GETs, which complete, to what an applied rekey
//! requires. `rk1-get-with-keys-kept-read-altered` hands the exact judge the
//! first client's read with its first byte changed.

use std::rc::Rc;

use crate::net::auth::KeyEntry;
use crate::sim::entropy::{nonce, nonce_site};

use super::super::{ACTORS, EPISODE_TURNS, EPISODE_US, PRINCIPALS, WAIT_US};
use super::*;

/// The rule of the time bound, which `narrate/rules.rs` lists among the mixed world's violations.
const STALLED: &str = "a healed request stalled past its bound";

/// The rule `World::watch_episodes` raises for an episode whose GET settled without its update.
const UNHEALED: &str = "a healed request settled without its update";

/// The rule of an exact read, which the counterpart's GETs are held to: the
/// histories' own text, because the rule catalog lets no history write a
/// text the single-owner world raises beside the oracle.
const INEXACT: &str = "a qualified GET missed the visible version's exact bytes";

const _: () = assert!(EPISODE_US == WAIT_US + crate::net::owner::MAINTAIN_REST_US);
const _: () = assert!(EPISODE_US == 201_000);

const SESSIONS: &str = "each client held an active session";
const REKEYED: &str = "the owner applied a rekey and its key epoch rose by one";
const KEPT: &str = "the owner kept its keys";
const ISSUED: &str = "each client issued a GET at the rekey's time";
const SETTLED: &str = "each client's GET settled within the episode's time and turn bounds";
const UNREAD: &str = "each GET after the rekey ended before any byte";
const EXACT: &str = "each GET completed with the object's exact bytes";

fn sessions_active(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.active(0) && world.active(1)
}

fn mark_sessions(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, SESSIONS)
}

/// The fault: a rekey applied at the owner, called as `World::deliver` calls it. The step keeps the
/// rekey's world time and the key epoch before it.
fn rekey(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let keys = [[0x70; 32], [0x71; 32]];
    let entries = [
        KeyEntry {
            principal: PRINCIPALS[0],
            key: &keys[0],
        },
        KeyEntry {
            principal: PRINCIPALS[1],
            key: &keys[1],
        },
    ];
    let before = world.scene.owner.key_epoch();
    let applied = {
        let (draws, refused) = (Rc::clone(&world.draws), &world.draw_refusal);
        let incarnation = draws.borrow_mut().launch(ACTORS[0]);
        let drawn = move |bytes: &mut [u8; 16]| {
            nonce(
                &mut draws.borrow_mut(),
                nonce_site(ACTORS[0]),
                incarnation,
                refused,
            )(bytes)
        };
        world
            .scene
            .owner
            .rekey_with_nonce(&entries, before + 1, now, drawn)
            .is_ok()
    };
    world.history.since = now;
    world.history.turn = world.seen.len();
    world.history.kept = u64::from(before);
    let rose = applied && world.scene.owner.key_epoch() == before + 1;
    premised(world, rose, REKEYED)
}

/// The counterpart: no rekey. The step keeps its world time and the key epoch.
fn keep_keys(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.since = now;
    world.history.turn = world.seen.len();
    world.history.kept = u64::from(world.scene.owner.key_epoch());
    mark(world, KEPT)
}

/// Issues one GET of the resident object from each client with wait `WAIT_US`, and wakes the run one
/// microsecond past the bound. The premise: both were issued at the time the step `rekey` ran, with the
/// key epoch that step left.
fn issue(world: &mut Mixed<'_, '_, '_>, now: u64, epoch: u64) -> u64 {
    let wanted = world.read.0;
    for client in 0..2 {
        if let Ok(id) = world.scene.clients[client].get(wanted, 0, 1 << 20, now, WAIT_US) {
            world.history.ids.push(id);
        }
    }
    world.history.wake = Some(world.history.since + EPISODE_US + 1);
    let formed = world.history.ids.len() == 2
        && now == world.history.since
        && u64::from(world.scene.owner.key_epoch()) == epoch;
    premised(world, formed, ISSUED)
}

fn issue_rekeyed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let epoch = world.history.kept + 1;
    issue(world, now, epoch)
}

fn issue_kept(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let epoch = world.history.kept;
    issue(world, now, epoch)
}

fn all_decided(world: &Mixed<'_, '_, '_>) -> bool {
    world.history.ids.len() == 2
        && (0..2).all(|client| {
            world.scene.clients[client]
                .outcome(world.history.ids[client])
                .is_some()
        })
}

/// Turns the run has taken since the step `rekey` ran.
fn turns(world: &Mixed<'_, '_, '_>) -> usize {
    world.seen.len() - world.history.turn
}

fn settled_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    all_decided(world) || now > world.history.since + EPISODE_US || turns(world) > EPISODE_TURNS
}

/// Each client's GET must be decided when the step samples it at time `seen`, at most `EPISODE_US`
/// after the rekey. The check also requires `turns <= EPISODE_TURNS`.
fn judge_settled(world: &mut Mixed<'_, '_, '_>, seen: u64, turns: usize) -> u64 {
    world.history.wake = None;
    let late = seen > world.history.since + EPISODE_US || turns > EPISODE_TURNS;
    if late || !all_decided(world) {
        return fail(world, Obligation::Progress, STALLED);
    }
    mark(world, SETTLED)
}

fn settled(world: &mut Mixed<'_, '_, '_>, seen: u64) -> u64 {
    let turns = turns(world);
    judge_settled(world, seen, turns)
}

/// A control: the settled GETs are judged one microsecond past the bound, as GETs first seen decided
/// then would be.
fn settled_late(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let seen = world.history.since + EPISODE_US + 1;
    let turns = turns(world);
    judge_settled(world, seen, turns)
}

/// At `EPISODE_TURNS + 1` turns, `judge_settled` fails `Obligation::Progress` with `STALLED` even
/// with both GETs decided inside the time bound.
fn settled_past_its_turns(world: &mut Mixed<'_, '_, '_>, seen: u64) -> u64 {
    judge_settled(world, seen, EPISODE_TURNS + 1)
}

/// Each GET's outcome and every byte it delivered, by client, after which its request retires.
fn results(world: &mut Mixed<'_, '_, '_>) -> [(Option<Outcome>, Vec<u8>); 2] {
    [0, 1].map(|client| {
        let id = world.history.ids[client];
        let bytes = drain(&mut world.scene.clients[client], id);
        let outcome = world.collect_get(client, id);
        let _ = world.scene.clients[client].retire(id);
        (outcome, bytes)
    })
}

/// After the applied rekey each GET ended before any byte, as `Episode::healed` requires.
fn ended_unread(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let unread = results(world).iter().all(|(outcome, bytes)| {
        bytes.is_empty()
            && outcome.is_some_and(|outcome| {
                !matches!(outcome, Outcome::Complete | Outcome::Incomplete(_))
            })
    });
    if !unread {
        return fail(world, Obligation::Progress, UNHEALED);
    }
    mark(world, UNREAD)
}

/// Judges the counterpart's `results`: each GET completed, the premise of its baseline, with the resident
/// object's exact bytes.
fn judge_exact_reads(
    world: &mut Mixed<'_, '_, '_>,
    results: &[(Option<Outcome>, Vec<u8>); 2],
) -> u64 {
    if results
        .iter()
        .any(|(outcome, _)| *outcome != Some(Outcome::Complete))
    {
        return premised(world, false, EXACT);
    }
    if results.iter().any(|(_, bytes)| *bytes != world.read.1) {
        return fail(world, Obligation::History, INEXACT);
    }
    mark(world, EXACT)
}

fn read_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let results = results(world);
    judge_exact_reads(world, &results)
}

/// A control: the first client's read is judged with its first byte changed, as a GET that completed
/// with other bytes than the object's would deliver it.
fn read_altered(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let mut results = results(world);
    if let Some(first) = results[0].1.first_mut() {
        *first ^= 0xff;
    }
    judge_exact_reads(world, &results)
}

const REKEY: [Step; 6] = [
    step("sessions", sessions_active, mark_sessions),
    step("rekey", always, rekey),
    step("gets", always, issue_rekeyed),
    step("settled", settled_or_late, settled),
    step("outcomes", always, ended_unread),
    JUDGE,
];

const NO_REKEY: [Step; 6] = replaced(
    replaced(
        replaced(REKEY, "rekey", step("rekey", always, keep_keys)),
        "gets",
        step("gets", always, issue_kept),
    ),
    "outcomes",
    step("outcomes", always, read_exact),
);

const REKEY_JUDGED_LATE: [Step; 6] = replaced(
    REKEY,
    "settled",
    step("settled-late", settled_or_late, settled_late),
);

const REKEY_JUDGED_PAST_ITS_TURNS: [Step; 6] = replaced(
    REKEY,
    "settled",
    step(
        "settled-past-its-turns",
        settled_or_late,
        settled_past_its_turns,
    ),
);

const NO_REKEY_JUDGED_AS_REKEYED: [Step; 6] = replaced(
    NO_REKEY,
    "outcomes",
    step("outcomes-as-rekeyed", always, ended_unread),
);

const NO_REKEY_READ_ALTERED: [Step; 6] = replaced(
    NO_REKEY,
    "outcomes",
    step("outcomes-altered", always, read_altered),
);

const REKEY_WITNESSES: &[&str] = &[SESSIONS, REKEYED, ISSUED, SETTLED, UNREAD];

const NO_REKEY_WITNESSES: &[&str] = &[SESSIONS, KEPT, ISSUED, SETTLED, EXACT];

const REKEY_JUDGED: &[Obligation] = &[Obligation::Progress];

const NO_REKEY_JUDGED: &[Obligation] = &[Obligation::Progress, Obligation::History];

/// The obligation each judging step's mark judges.
pub(super) const CHECKS: [(&str, Obligation); 3] = [
    (SETTLED, Obligation::Progress),
    (UNREAD, Obligation::Progress),
    (EXACT, Obligation::History),
];

pub(super) const REKEYS: [History; 6] = [
    history(
        "rk1-get-after-a-rekey",
        &REKEY,
        REKEY_WITNESSES,
        REKEY_JUDGED,
        Expect::Pass,
    ),
    history(
        "rk1-get-with-keys-kept",
        &NO_REKEY,
        NO_REKEY_WITNESSES,
        NO_REKEY_JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "rk1-get-after-a-rekey-judged-late",
            &REKEY_JUDGED_LATE,
            REKEY_WITNESSES,
            REKEY_JUDGED,
            Expect::Violation(Obligation::Progress, STALLED),
        ),
        &[REKEYED, ISSUED],
    ),
    control(
        history(
            "rk1-get-after-a-rekey-judged-past-its-turns",
            &REKEY_JUDGED_PAST_ITS_TURNS,
            REKEY_WITNESSES,
            REKEY_JUDGED,
            Expect::Violation(Obligation::Progress, STALLED),
        ),
        &[REKEYED, ISSUED],
    ),
    control(
        history(
            "rk1-get-with-keys-kept-judged-as-rekeyed",
            &NO_REKEY_JUDGED_AS_REKEYED,
            NO_REKEY_WITNESSES,
            NO_REKEY_JUDGED,
            Expect::Violation(Obligation::Progress, UNHEALED),
        ),
        &[KEPT, ISSUED, SETTLED],
    ),
    control(
        history(
            "rk1-get-with-keys-kept-read-altered",
            &NO_REKEY_READ_ALTERED,
            NO_REKEY_WITNESSES,
            NO_REKEY_JUDGED,
            Expect::Violation(Obligation::History, INEXACT),
        ),
        &[KEPT, ISSUED, SETTLED],
    ),
];
