//! LW judges the lending order of write commands between two peers' uploads, in three families:
//! LW1 after refused device submits of a one-fragment waiter, LW2 after a receive refused for an
//! empty buffer pool, and LW3 after a device submit refused inside a receive that takes part of a
//! fragment.
//!
//! Property: the module documentation of `net/put.rs`, "Write commands": "So from the turn after
//! such a peer first finds none, and while a PUT of a peer below its share ends each turn with a
//! write to submit and no command for it, every command goes to a peer below its share." The PUT
//! core's library test `a_freed_write_command_goes_to_the_peer_below_its_share` asserts it. RULE
//! below (array `MIXED` of `narrate/rules.rs`) states it, and [`Lending::turn`] raises it under
//! `Obligation::Progress`.
//!
//! The borrower is client 1's upload (peer 1, key 2, six fragments, admitted first) and the waiter
//! client 0's (peer 0, key 1, admitted second). The owner runs with a budget of one write command
//! a turn over the storage of three fill records and six receive-write buffers. A peer's share is
//! two of the device's four write slots, and the device holds every write, so no command ends
//! before the release step. The turn step runs five owner turns itself, with no chooser event and
//! no world time between them. In LW1 the waiter's object is one fragment, so a buffer is free in
//! every turn:
//!
//! 1. Client 1 sends the borrower's last two fragments. The turn's command is the borrower's
//!    second: it holds its share.
//! 2. Client 0 sends the waiter's fragment. The turn lends, the borrower, visited first, takes its
//!    third command, and the waiter finds the budget spent, which the owner counts as a wait. The
//!    next turn lends nothing.
//! 3. The waiter alone may take the command.
//! 4. As turn 3 while the waiter still waits.
//! 5. The last turn the check judges.
//!
//! The check runs after each of the five turns while both uploads are undecided. It reads the
//! undelivered write commands of each upload from the device's capture by fill serial, whether the
//! turn lent (`Owner::put_lends`), and the waits the owner and the device counted. The rule binds
//! in a turn when the turn before it lent nothing and the waiter, below its share, ended that turn
//! with no new command while a wait was counted. The counts are totals over both uploads, and each
//! history's premise attributes the wait of the turn it names to the waiter. The first turn that
//! lends nothing is outside the check, which the PUT core's library test above covers. A new
//! command of the borrower in a bound turn, with the borrower at its share before the turn, fails
//! RULE. After each turn the check also requires each peer's one upload active at the owner, and
//! each premise of a judged turn requires the check's own predicate to bind the rule in that
//! turn. Each premise reads state both an owner that
//! keeps the rule and one that breaks it have, and a premise that does not form ends the run
//! unsuccessful under its name.
//!
//! - `lw1-waiter-submit-refused-twice`: the device refuses one submit (`QueueFull`) in turn 3 and
//!   one in turn 4. The first lands inside the receive that takes the waiter's fragment, which
//!   returns its bytes and leaves the segment staged; the pass then finds the budget spent and
//!   notes the wait, so turn 4 lends nothing. The second lands on the retry of the staged segment,
//!   a refused receive (`TableFull`). `PutCore::receive_wait` notes a wait only for a spent budget,
//!   so turn 5 lends and the borrower takes a fourth command while the waiter holds none: RULE. An
//!   owner that notes the refused retry gives turn 5's command to the waiter, and the history
//!   passes. The premise REFUSED records two scripted refusals taken, one refused receive counted,
//!   the borrower at three commands, the waiter at none and turn 4 lending nothing.
//! - `lw1-waiter-submit-accepted`: the same steps with no refusal. The waiter takes turn 3's
//!   command, the rule stops binding, and the borrower's fourth command in turn 4 is lawful.
//! - `lw1-waiter-submit-refused-once`: one refusal, in turn 3. It lands inside the receive that
//!   takes the waiter's fragment and spends the turn's command, the same pass notes the wait, and
//!   turn 4 lends nothing: a bound turn in which the waiter takes the command, and the history
//!   passes.
//! - In the `lw1-accepted-turn-judged-as-bound` control, the sibling's turn step tells the check
//!   that the rule binds in turn 2, so the borrower's lawful third command fails RULE. The plant
//!   changes only the check's state: the owner's turn 2 runs as in the sibling. The control shows
//!   what the check reads.
//! - `lw1-refusals-unqueued` falsifies REFUSED: the pin's premises with no refusal queued end the
//!   run unsuccessful.
//!
//! LW2 runs the same steps with no refusal and a waiter of four fragments, which fill its first two
//! segments, so the tail of its last fragment needs a third buffer. The borrower holds four of the
//! storage's six receive-write buffers once its last fragment arrives, and the waiter's first two
//! take the rest.
//!
//! - `lw2-waiter-receive-finds-no-buffer`: the waiter's fragments reach the owner with the
//!   borrower's last two. Turn 1 gives the borrower its second command and the waiter a counted
//!   wait. Turn 2 lends nothing and the waiter writes its second segment. Turn 3 lends, the
//!   borrower takes its third command and the waiter finds the budget spent. Turn 4 lends nothing:
//!   the waiter's receive of its last fragment's tail is refused for an empty buffer pool
//!   (`PoolExhausted`) while the volume admits a command. `PutCore::receive_wait` notes no wait
//!   for it, so turn 5 lends and the borrower takes a fourth command while the waiter holds one:
//!   RULE. An owner that notes the refused receive gives turn 5 no command, and the history passes.
//!   The premise EXHAUSTED records one refused receive in turn 4, no scripted refusal, the
//!   borrower at three commands, the waiter at one and turn 4 lending nothing.
//! - `lw2-waiter-fragments-one-turn-later`: the waiter's fragments reach the owner one turn
//!   later. The borrower takes its fourth command in turn 4, a turn that lends after the waiter
//!   wrote in turn 3, and the volume then admits no command, which the owner notes as a wait
//!   before any receive. No receive is refused for a buffer, and the history passes.
//! - `lw2-later-fragments-read-as-refused` falsifies EXHAUSTED: the sibling's steps under the
//!   pin's premise end the run unsuccessful.
//!
//! LW3 runs LW2's sibling steps with one refusal. Its pin fails through the refused submit that
//! `PutCore::receive` reports as no wait, and LW1's pin through the refused retry that
//! `PutCore::receive_wait` notes as none.
//!
//! - `lw3-waiter-submit-refused-inside-fragment`: the waiter's fragments reach the owner one turn
//!   later, and the device refuses one submit (`QueueFull`) in turn 3, a turn that lends nothing.
//!   The waiter's second segment ends inside its last fragment, so the receive of that fragment
//!   takes the bytes up to the segment's end, the device refuses the segment's submit, and the
//!   receive returns the bytes it took. `PutCore::receive` reports a refused submit only when the
//!   budget refused it, and `PutCore::consume` ends the pass after a receive that takes part of a
//!   fragment, so the owner notes no wait. Turn 4 lends and the borrower takes a fourth command
//!   while the waiter holds none: RULE. An owner that notes the refused submit gives turn 4's
//!   command to the waiter, and the history passes. The premise STOPPED records, for turn 3, one
//!   device refusal taken, no refused receive counted, copies that end inside a fragment, the
//!   borrower at three commands, the waiter at none before and after, and no lending. Its
//!   sibling is `lw2-waiter-fragments-one-turn-later`, the same steps with no refusal.
//! - `lw3-refusal-unqueued` falsifies STOPPED: the pin's steps with no refusal queued end the run
//!   unsuccessful.
//!
//! The listing holds six of the ten histories, which the sweep and the fresh-process replay run:
//! the three pins, `lw1-waiter-submit-accepted`, `lw2-waiter-fragments-one-turn-later` and the
//! control. The three falsifiers and `lw1-waiter-submit-refused-once` run in process under the
//! pinned roots, in the seeded test of `SEEDED`.
//!
//! When the waiter's receive spends the turn's command on a submit and then stops for a buffer,
//! the owner lends the borrower a command on the owner's next turn. In turn 2 of the pin and
//! turn 3 of the sibling the waiter's receive submits its second segment, finds no buffer for
//! its last fragment's tail and returns the bytes it took. `PutCore::consume` notes a wait after
//! a receive that takes part of a fragment when the budget refused a submit, and the volume
//! accepts this receive's one submit. With a buffer free, the same receive takes the tail, the
//! budget refuses the submit of the last segment, and the owner notes the wait. The borrower
//! then takes its third command in the pin and its fourth in the sibling while the waiter holds
//! the tail. [`Lending::turn`] binds RULE after a turn in which the waiter took no command, and
//! the waiter took one command in turn 2 of the pin and in turn 3 of the sibling. EXHAUSTED and
//! SPARED require the borrower's two commands. Under an owner that notes a wait at the buffer
//! stop, both histories end unsuccessful.

use crate::storage::device::sim::Origin;
use crate::storage::device::{RefusalReason, SubmitRefusal};

use super::super::super::adapters::written_commands;
use super::super::super::datagram::PeerId;
use super::super::{Geometry, TTL_MS, WAIT_US};
use super::*;

/// The rule LW judges.
const RULE: &str =
    "a write command went to a peer at its share while a peer below its share waited";

/// A peer's write share: the device's four write slots over two peers.
const SHARE: usize = 2;

const FIRST: &str = "the borrower was admitted first";
const AT_SHARE: &str = "the borrower held its share of two";
const WAITED: &str = "the waiter waited at a spent budget";
const REFUSED: &str = "two refusals kept the waiter waiting";
const REFUSED_ONCE: &str = "one refusal left the next turn bound";
const TOOK: &str = "the waiter took the next command";
const EXHAUSTED: &str = "the waiter's receive found no buffer";
const SPARED: &str = "no receive was refused for a buffer";
const STOPPED: &str = "one refusal split the waiter's fragment";
const SENT: &str = "the waiter's fragments left its client";
const LIVE: &str = "each peer held its one upload active";
const ORDERED: &str = "write commands kept the lending order";
const BORROWER_PUBLISHED: &str = "the borrower's upload published";

pub(super) const CHECKS: [(&str, Obligation); 1] = [(ORDERED, Obligation::Progress)];

/// The borrower's object: six fragments, which the owner writes in four
/// commands once the last fragment arrives.
fn lent() -> Vec<u8> {
    payload(6 * FRAGMENT_LEN as usize, 5)
}

/// Holds every write command the device accepts, so no write ends before
/// the release step.
fn hold_writes(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_writes = true;
    1
}

fn borrower_begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let version = CacheVersion(0);
    let Ok(id) = world.scene.clients[1].put(key(2), version, now, WAIT_US) else {
        return STAY;
    };
    world.plan.puts -= 1;
    world
        .registry
        .borrow_mut()
        .register(key(2), LABEL_C, 0, lent());
    world.history.second = Some(id);
    1
}

/// Sends the PREPARE of `client`'s upload `id` for a body of `len` bytes.
fn prepared(
    world: &mut Mixed<'_, '_, '_>,
    client: usize,
    id: Option<RequestId>,
    len: usize,
) -> u64 {
    let id = id.expect("a begun upload");
    match world.scene.clients[client].prepare(id, 0, len as u32, TTL_MS) {
        Ok(()) => 1,
        Err(_) => STAY,
    }
}

/// The owner's READY reached `client` for its upload `id`, which then
/// takes fragments.
fn granted(world: &Mixed<'_, '_, '_>, client: usize, id: Option<RequestId>) -> bool {
    id.and_then(|id| world.scene.clients[client].put_receipt(id))
        .is_some_and(|(_, _, grant)| grant > 0)
}

/// The borrower holds its grant, and client 0 holds a session.
fn borrower_granted(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    active_put(world, now) && granted(world, 1, world.history.second)
}

/// Begins the waiter's upload of `object`, keeping the table slot of the
/// one PUT the owner holds before it: the borrower's, which the admission
/// order then lists first. With no PUT held the kept value matches no slot.
fn waiter_begin_with(world: &mut Mixed<'_, '_, '_>, now: u64, object: Vec<u8>) -> u64 {
    let order = world.scene.owner.put_admission_order();
    world.history.kept = order.first().map_or(u64::MAX, |&slot| u64::from(slot));
    put_begin_with(world, CacheVersion(0), object, LABEL_B, now)
}

fn waiter_begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    waiter_begin_with(world, now, version_b())
}

/// LW2's waiter: four fragments, which fill the upload's first two
/// segments, so the last fragment's tail needs a third buffer.
fn long_waiter() -> Vec<u8> {
    payload(4 * FRAGMENT_LEN as usize, 6)
}

fn long_waiter_begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    waiter_begin_with(world, now, long_waiter())
}

/// Client 0 supplies the waiter's whole `object` and sends it.
fn waiter_sent(world: &mut Mixed<'_, '_, '_>, now: u64, object: &[u8]) -> bool {
    let id = world.history.put.expect("the waiter");
    let mut fragments = object.chunks(FRAGMENT_LEN as usize).enumerate();
    fragments.all(|(index, bytes)| {
        world.scene.clients[0]
            .supply(id, index as u32, bytes)
            .is_ok()
    }) && sent(world, 0, now)
}

/// Supplies the borrower's fragments in `fragments`; false when the client
/// refused one.
fn supplied(world: &mut Mixed<'_, '_, '_>, fragments: std::ops::Range<u32>) -> bool {
    let id = world.history.second.expect("the borrower");
    let object = lent();
    fragments.into_iter().all(|index| {
        let at = (index * FRAGMENT_LEN) as usize;
        let bytes = &object[at..at + FRAGMENT_LEN as usize];
        world.scene.clients[1].supply(id, index, bytes).is_ok()
    })
}

fn borrower_supply(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if supplied(world, 0..4) { 1 } else { STAY }
}

/// The undelivered write commands of the borrower and of the waiter, in
/// that order, as the device's capture holds them under each upload's fill
/// serial.
fn commands(world: &Mixed<'_, '_, '_>) -> [usize; 2] {
    let capture = world.scene.control.capture();
    [(1, world.history.second), (0, world.history.put)].map(|(client, id)| {
        let receipt = id.and_then(|id| world.scene.clients[client].put_receipt(id));
        let Some((serial, _, _)) = receipt else {
            return 0;
        };
        written_commands(world.scene.owner.volume_bound(), &capture, serial)
            .iter()
            .filter(|command| command.delivered.is_none())
            .count()
    })
}

/// The borrower holds one undelivered write command, client 1 has two
/// source slots free for the last two fragments, and the waiter holds its
/// grant.
fn uploads_ready(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    let slots = world.scene.clients[1].sources();
    commands(world)[0] == 1
        && slots.iter().filter(|slot| slot.piece().is_none()).count() >= 2
        && granted(world, 0, world.history.put)
}

/// The waits the owner and the device counted, over every upload: PUTs
/// that found no command, receives the volume refused, and submits the
/// device refused.
fn waits(world: &Mixed<'_, '_, '_>) -> u64 {
    let report = world.scene.owner.put_report();
    report.command_waits + report.receive_waits + refusals(world) as u64
}

fn refusals(world: &Mixed<'_, '_, '_>) -> usize {
    world.scene.control.refused(Origin::Script) + world.scene.control.refused(Origin::Model)
}

/// Client `client` sends what it owes: a datagram joins those its link
/// holds for the owner.
fn sent(world: &mut Mixed<'_, '_, '_>, client: usize, now: u64) -> bool {
    let toward = world.scene.nets[client].borrow().receivable(1);
    let _ = world.scene.clients[client].poll(now);
    world.scene.nets[client].borrow().receivable(1) > toward
}

/// The check's state between the turns of one step: whether the rule binds
/// in the next turn.
#[derive(Default)]
struct Lending {
    bound: bool,
}

impl Lending {
    /// One owner turn under the check. The rule binds in a turn when the
    /// turn before it lent nothing and the waiter, below its share, ended
    /// that turn with no new command while a wait was counted. The count is
    /// the owner's and the device's total, so a caller forms the premise
    /// that the waiter held the write that waited before the turn it
    /// judges. After each turn both peers hold one active request and none
    /// draining, or the run ends unsuccessful under LIVE. In a bound turn a
    /// new command of the borrower, at its share before the turn, fails
    /// RULE. The result is whether the run goes on.
    fn turn(&mut self, world: &mut Mixed<'_, '_, '_>, now: u64) -> bool {
        let (before, waited) = (commands(world), waits(world));
        world.owner_turn(now);
        let after = commands(world);
        let live = [0, 1].into_iter().all(|peer| {
            let census = world.scene.owner.peer_census(PeerId(peer));
            (census.active, census.draining) == (1, 0)
        });
        if !live {
            premised(world, false, LIVE);
            return false;
        }
        if self.bound && before[0] >= SHARE && after[0] > before[0] {
            fail(world, Obligation::Progress, RULE);
            return false;
        }
        self.bound = !world.scene.owner.put_lends()
            && before[1] < SHARE
            && after[1] == before[1]
            && waits(world) > waited;
        true
    }
}

/// What LW1's turn step does in its third and fourth turns.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    /// The device refuses the waiter's submit in each of the two turns.
    Refused,
    /// The device refuses the waiter's submit in the third turn alone.
    RefusedOnce,
    /// No refusal: the waiter takes the command of the turn that lends
    /// nothing.
    Accepted,
    /// [`Case::Refused`]'s premise with no refusal queued.
    Unqueued,
    /// [`Case::Accepted`] with the check told that the rule binds in the
    /// turn the borrower takes its third command.
    ToldBound,
}

/// What a turn showed: device refusals taken, refused receives counted,
/// the commands after it, whether it lent, and whether the rule binds in
/// the turn after it.
type Shown = (usize, u64, [usize; 2], bool, bool);

/// One turn under the check and what it showed, or `None` when the turn
/// ended the run: it failed RULE, or a peer held other than its one active
/// upload.
fn shown(world: &mut Mixed<'_, '_, '_>, now: u64, lending: &mut Lending) -> Option<Shown> {
    let refused = refusals(world);
    let receives = world.scene.owner.put_report().receive_waits;
    lending.turn(world, now).then(|| {
        (
            refusals(world) - refused,
            world.scene.owner.put_report().receive_waits - receives,
            commands(world),
            world.scene.owner.put_lends(),
            lending.bound,
        )
    })
}

/// The premise both turn steps start from: the owner admitted the borrower
/// first, and both uploads are undecided and hold their grants, so
/// [`commands`] reads each by its fill serial.
fn admitted_first(world: &mut Mixed<'_, '_, '_>, now: u64) -> bool {
    let order = world.scene.owner.put_admission_order();
    let borrower = world.history.second.expect("the borrower");
    let undecided =
        world.scene.clients[1].put_outcome(borrower).is_none() && !put_decided(world, now);
    let first = order.len() == 2 && u64::from(order[0]) == world.history.kept;
    let granted = granted(world, 1, Some(borrower)) && granted(world, 0, world.history.put);
    premised(world, first && undecided && granted, FIRST) != 0
}

/// The first turn of both turn steps: client 1 sends the borrower's last
/// two fragments, which complete its other three writes, client 0 sends
/// `waiter` when given, and the turn's one command is the borrower's
/// second. Returns the check's state, or `None` once the run ended.
fn opened(world: &mut Mixed<'_, '_, '_>, now: u64, waiter: Option<&[u8]>) -> Option<Lending> {
    if !admitted_first(world, now) {
        return None;
    }
    let mut lending = Lending::default();
    let formed = supplied(world, 4..6)
        && sent(world, 1, now)
        && waiter.is_none_or(|object| waiter_sent(world, now, object));
    if !formed {
        premised(world, false, AT_SHARE);
        return None;
    }
    let kept = lending.turn(world, now);
    (kept && premised(world, commands(world) == [SHARE, 0], AT_SHARE) != 0).then_some(lending)
}

/// LW1's clock: five owner turns with no chooser event and no world time
/// between them, each under [`Lending::turn`].
fn turns(world: &mut Mixed<'_, '_, '_>, now: u64, case: Case) -> u64 {
    let Some(mut lending) = opened(world, now, None) else {
        return 0;
    };
    if !waiter_sent(world, now, &version_b()) {
        return premised(world, false, WAITED);
    }
    let counted = world.scene.owner.put_report().command_waits;
    // The control's plant: the check is told that the rule binds in the
    // second turn, which the owner runs as in the sibling.
    if case == Case::ToldBound {
        lending.bound = true;
    }
    // This turn lends: the borrower, visited first, takes the one command,
    // and the waiter finds the budget spent.
    if !lending.turn(world, now) {
        return 0;
    }
    let waited = world.scene.owner.put_report().command_waits > counted;
    if premised(world, waited && commands(world) == [SHARE + 1, 0], WAITED) == 0 {
        return 0;
    }
    let queued = match case {
        Case::Refused => 2,
        Case::RefusedOnce => 1,
        Case::Accepted | Case::Unqueued | Case::ToldBound => 0,
    };
    let mut seen = [None; 2];
    for (at, seen) in seen.iter_mut().enumerate() {
        if at < queued {
            let reason = RefusalReason::QueueFull;
            world
                .scene
                .control
                .refuse_next(SubmitRefusal { reason, code: None });
        }
        *seen = shown(world, now, &mut lending);
        if seen.is_none() {
            return 0;
        }
    }
    // A refusal inside the receive that takes the waiter's fragment leaves
    // its segment staged and the turn's command spent, which the owner
    // notes as a wait. A refusal of the staged segment's retry is the one
    // refused receive the owner counts.
    let absorbed = Some((1, 0, [SHARE + 1, 0], false, true));
    let took = Some((0, 0, [SHARE + 1, 1], false, false));
    let (premise, expected) = match case {
        Case::Refused | Case::Unqueued => (
            REFUSED,
            [absorbed, Some((1, 1, [SHARE + 1, 0], false, true))],
        ),
        Case::RefusedOnce => (REFUSED_ONCE, [absorbed, took]),
        Case::Accepted | Case::ToldBound => {
            (TOOK, [took, Some((0, 0, [SHARE + 2, 1], true, false))])
        }
    };
    if premised(world, seen == expected, premise) == 0 || !lending.turn(world, now) {
        return 0;
    }
    mark(world, ORDERED)
}

/// What the turn step of LW2 and LW3 sends when, and the premise its
/// judged turn forms.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pool {
    /// The waiter's fragments reach the owner with the borrower's last
    /// two, and the fourth turn forms EXHAUSTED.
    Exhausted,
    /// The waiter's fragments reach the owner one turn later, and the
    /// fourth turn forms SPARED.
    Late,
    /// [`Pool::Late`]'s sends under [`Pool::Exhausted`]'s premise.
    LateAsExhausted,
    /// [`Pool::Late`]'s sends with the device refusing the waiter's submit
    /// in the third turn, which forms STOPPED.
    Stopped,
    /// [`Pool::Stopped`]'s premise with no refusal queued.
    Unstopped,
}

/// The clock of LW2 and LW3: five owner turns as [`turns`] takes them.
/// EXHAUSTED is a fourth turn that lent nothing, counted one refused
/// receive and zero device refusals, and left the borrower at three
/// commands and the waiter at one: the waiter's receive, since the
/// borrower at its share takes no command in such a turn and so reaches no
/// receive. STOPPED is a third turn that lent nothing, took one device
/// refusal, counted no refused receive, copied a byte count that is no
/// whole number of fragments, and left the borrower at three commands and
/// the waiter at none: the waiter's submit inside a fragment, since the
/// borrower beyond its share takes no command in such a turn and so copies
/// and submits nothing. A send the waiter's client refuses ends the run
/// unsuccessful under SENT.
fn pooled(world: &mut Mixed<'_, '_, '_>, now: u64, pool: Pool) -> u64 {
    let object = long_waiter();
    let late = pool != Pool::Exhausted;
    let Some(mut lending) = opened(world, now, (!late).then_some(&object[..])) else {
        return 0;
    };
    let (premise, judged) = match pool {
        Pool::Exhausted | Pool::LateAsExhausted => (EXHAUSTED, 4),
        Pool::Late => (SPARED, 4),
        Pool::Stopped | Pool::Unstopped => (STOPPED, 3),
    };
    if late && !waiter_sent(world, now, &object) {
        return premised(world, false, SENT);
    }
    // By either order the borrower holds three commands after the second
    // turn, and the waiter one after the third when the device refuses
    // nothing.
    for _ in 2..judged {
        if !lending.turn(world, now) {
            return 0;
        }
    }
    if pool == Pool::Stopped {
        let reason = RefusalReason::QueueFull;
        world
            .scene
            .control
            .refuse_next(SubmitRefusal { reason, code: None });
    }
    let before = commands(world);
    let Some(seen) = shown(world, now, &mut lending) else {
        return 0;
    };
    let formed = match pool {
        Pool::Exhausted | Pool::LateAsExhausted => {
            before == [SHARE + 1, 1] && seen == (0, 1, before, false, true)
        }
        Pool::Late => before == [SHARE + 1, 1] && seen == (0, 0, [SHARE + 2, 1], true, false),
        Pool::Stopped | Pool::Unstopped => {
            let copied = world.scene.owner.put_turn_copy_bytes();
            before == [SHARE + 1, 0]
                && seen == (1, 0, before, false, true)
                && !copied.is_multiple_of(FRAGMENT_LEN as usize)
        }
    };
    if premised(world, formed, premise) == 0 {
        return 0;
    }
    for _ in judged..5 {
        if !lending.turn(world, now) {
            return 0;
        }
    }
    mark(world, ORDERED)
}

fn borrower_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    let decided = |id| world.scene.clients[1].put_outcome(id).is_some();
    world.history.second.is_some_and(decided)
}

fn borrower_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.second.expect("the borrower");
    let outcome = world.collect_put_at(1, id);
    let _ = world.scene.clients[1].retire(id);
    if outcome != Some(UploadOutcome::Published) {
        return fail(
            world,
            Obligation::History,
            "the upload's result was other than published",
        );
    }
    mark(world, BORROWER_PUBLISHED)
}

const REFUSED_TWICE: [Step; 11] = [
    step("hold-writes", always, hold_writes),
    step("borrower-begin", active_get, borrower_begin),
    step("borrower-prepare", always, |world, _| {
        prepared(world, 1, world.history.second, lent().len())
    }),
    step("waiter-begin", borrower_granted, waiter_begin),
    step("waiter-prepare", always, put_prepare),
    step("borrower-supply", always, borrower_supply),
    step("turns-refused", uploads_ready, |world, now| {
        turns(world, now, Case::Refused)
    }),
    step("release", always, release_reads),
    step("borrower-published", borrower_decided, borrower_published),
    step("waiter-published", put_decided, put_published),
    JUDGE,
];

const ACCEPTED: [Step; 11] = replaced(
    REFUSED_TWICE,
    "turns-refused",
    step("turns-accepted", uploads_ready, |world, now| {
        turns(world, now, Case::Accepted)
    }),
);

const REFUSED_ONCE_SCRIPT: [Step; 11] = replaced(
    REFUSED_TWICE,
    "turns-refused",
    step("turns-refused-once", uploads_ready, |world, now| {
        turns(world, now, Case::RefusedOnce)
    }),
);

const UNQUEUED: [Step; 11] = replaced(
    REFUSED_TWICE,
    "turns-refused",
    step("turns-unqueued", uploads_ready, |world, now| {
        turns(world, now, Case::Unqueued)
    }),
);

const TOLD_BOUND: [Step; 11] = replaced(
    REFUSED_TWICE,
    "turns-refused",
    step("turns-told-bound", uploads_ready, |world, now| {
        turns(world, now, Case::ToldBound)
    }),
);

const EXHAUSTING: [Step; 11] = replaced(
    replaced(
        replaced(
            REFUSED_TWICE,
            "waiter-begin",
            step("long-waiter-begin", borrower_granted, long_waiter_begin),
        ),
        "waiter-prepare",
        step("long-waiter-prepare", always, |world, _| {
            prepared(world, 0, world.history.put, long_waiter().len())
        }),
    ),
    "turns-refused",
    step("turns-exhausted", uploads_ready, |world, now| {
        pooled(world, now, Pool::Exhausted)
    }),
);

const LATE: [Step; 11] = replaced(
    EXHAUSTING,
    "turns-exhausted",
    step("turns-late", uploads_ready, |world, now| {
        pooled(world, now, Pool::Late)
    }),
);

const LATE_AS_EXHAUSTED: [Step; 11] = replaced(
    EXHAUSTING,
    "turns-exhausted",
    step("turns-late-as-exhausted", uploads_ready, |world, now| {
        pooled(world, now, Pool::LateAsExhausted)
    }),
);

const STOPPING: [Step; 11] = replaced(
    EXHAUSTING,
    "turns-exhausted",
    step("turns-stopped", uploads_ready, |world, now| {
        pooled(world, now, Pool::Stopped)
    }),
);

const UNSTOPPED: [Step; 11] = replaced(
    EXHAUSTING,
    "turns-exhausted",
    step("turns-unstopped", uploads_ready, |world, now| {
        pooled(world, now, Pool::Unstopped)
    }),
);

const REFUSED_WITNESSES: &[&str] = &[
    FIRST,
    AT_SHARE,
    WAITED,
    REFUSED,
    ORDERED,
    BORROWER_PUBLISHED,
    "upload published",
];
const REFUSED_ONCE_WITNESSES: &[&str] = &[
    FIRST,
    AT_SHARE,
    WAITED,
    REFUSED_ONCE,
    ORDERED,
    BORROWER_PUBLISHED,
    "upload published",
];
const ACCEPTED_WITNESSES: &[&str] = &[
    FIRST,
    AT_SHARE,
    WAITED,
    TOOK,
    ORDERED,
    BORROWER_PUBLISHED,
    "upload published",
];
const EXHAUSTED_WITNESSES: &[&str] = &[
    FIRST,
    AT_SHARE,
    EXHAUSTED,
    ORDERED,
    BORROWER_PUBLISHED,
    "upload published",
];
const SPARED_WITNESSES: &[&str] = &[
    FIRST,
    AT_SHARE,
    SPARED,
    ORDERED,
    BORROWER_PUBLISHED,
    "upload published",
];
const STOPPED_WITNESSES: &[&str] = &[
    FIRST,
    AT_SHARE,
    STOPPED,
    ORDERED,
    BORROWER_PUBLISHED,
    "upload published",
];
const REFUSED_PREMISE: &[&str] = &[FIRST, AT_SHARE, WAITED, REFUSED];
const EXHAUSTED_PREMISE: &[&str] = &[FIRST, AT_SHARE, EXHAUSTED];
const STOPPED_PREMISE: &[&str] = &[FIRST, AT_SHARE, STOPPED];
const JUDGED: &[Obligation] = &[Obligation::Progress, Obligation::History];

/// LW2's source bytes: client 1's four source slots and the waiter's four
/// fragments.
const LONG_SOURCE_BYTES: u32 = 8 * FRAGMENT_LEN;

/// An LW history: two uploads, client 1's from four source slots, under a
/// budget of one write command a turn, over the storage of three fill
/// records. Its source bytes are LW1's: client 1's four slots and the
/// waiter's one fragment.
const fn lent_history(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    expect: Expect,
) -> History {
    History {
        uploads: 2,
        source_bytes: 5 * FRAGMENT_LEN,
        gets: [0, 0],
        put_commands: Some(1),
        second_sources: 4,
        geometry: Geometry::ThreeFills,
        ..history(name, script, witnesses, JUDGED, expect)
    }
}

/// The listed LW histories: each pin, the passing sibling of each
/// known-findings row, and the control of RULE. The sweep and the
/// fresh-process replay run these.
pub(super) const LENT_COMMANDS: [History; 6] = [
    control(
        lent_history(
            "lw1-waiter-submit-refused-twice",
            &REFUSED_TWICE,
            REFUSED_WITNESSES,
            Expect::Violation(Obligation::Progress, RULE),
        ),
        REFUSED_PREMISE,
    ),
    lent_history(
        "lw1-waiter-submit-accepted",
        &ACCEPTED,
        ACCEPTED_WITNESSES,
        Expect::Pass,
    ),
    control(
        lent_history(
            "lw1-accepted-turn-judged-as-bound",
            &TOLD_BOUND,
            ACCEPTED_WITNESSES,
            Expect::Violation(Obligation::Progress, RULE),
        ),
        &[FIRST, AT_SHARE],
    ),
    control(
        sourcing(
            lent_history(
                "lw2-waiter-receive-finds-no-buffer",
                &EXHAUSTING,
                EXHAUSTED_WITNESSES,
                Expect::Violation(Obligation::Progress, RULE),
            ),
            LONG_SOURCE_BYTES,
        ),
        EXHAUSTED_PREMISE,
    ),
    sourcing(
        lent_history(
            "lw2-waiter-fragments-one-turn-later",
            &LATE,
            SPARED_WITNESSES,
            Expect::Pass,
        ),
        LONG_SOURCE_BYTES,
    ),
    control(
        sourcing(
            lent_history(
                "lw3-waiter-submit-refused-inside-fragment",
                &STOPPING,
                STOPPED_WITNESSES,
                Expect::Violation(Obligation::Progress, RULE),
            ),
            LONG_SOURCE_BYTES,
        ),
        STOPPED_PREMISE,
    ),
];

/// The LW histories outside the listing, which the seeded test below runs
/// in process under the pinned roots: the falsifier of each pin's premise
/// and the one-refusal history whose bound turn the check passes. Each
/// shows a property of the family's steps and registers no finding.
const SEEDED: &[History] = &[
    control(
        lent_history(
            "lw1-refusals-unqueued",
            &UNQUEUED,
            REFUSED_WITNESSES,
            Expect::Unsuccessful(REFUSED),
        ),
        REFUSED_PREMISE,
    ),
    lent_history(
        "lw1-waiter-submit-refused-once",
        &REFUSED_ONCE_SCRIPT,
        REFUSED_ONCE_WITNESSES,
        Expect::Pass,
    ),
    control(
        sourcing(
            lent_history(
                "lw2-later-fragments-read-as-refused",
                &LATE_AS_EXHAUSTED,
                EXHAUSTED_WITNESSES,
                Expect::Unsuccessful(EXHAUSTED),
            ),
            LONG_SOURCE_BYTES,
        ),
        EXHAUSTED_PREMISE,
    ),
    control(
        sourcing(
            lent_history(
                "lw3-refusal-unqueued",
                &UNSTOPPED,
                STOPPED_WITNESSES,
                Expect::Unsuccessful(STOPPED),
            ),
            LONG_SOURCE_BYTES,
        ),
        STOPPED_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use super::super::super::bundle::held_by;
    use super::super::tests::{ROOTS, ends_as_declared_at, first_failure, run_end};
    use super::{Expect, FRAGMENT_LEN, LENT_COMMANDS, SEEDED};
    use crate::sim::turn::End;

    /// The clients hold client 1's four source slots and the waiter's
    /// object at once, so admission bounds `source_bytes` at their sum.
    #[test]
    fn each_lw_history_holds_the_source_bytes_of_its_two_clients() {
        for history in &LENT_COMMANDS {
            let waiter = if history.name.starts_with("lw1-") {
                1
            } else {
                4
            };
            let held = held_by(history.name).expect("a listed history");
            let source = held.iter().find(|(key, _)| *key == "source_bytes");
            assert_eq!(
                source.expect("a source-byte bound").1,
                u64::from((4 + waiter) * FRAGMENT_LEN),
                "{}",
                history.name
            );
        }
    }

    /// Each listed LW history ends as it declares under the sibling
    /// families' pinned roots, and its bundle replays equal.
    #[test]
    fn the_lent_command_family_ends_as_declared_under_pinned_roots() {
        for history in &LENT_COMMANDS {
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

    /// Each history of `SEEDED` reaches its goal under the pinned roots
    /// with the first failure it declares: a falsifier ends unsuccessful
    /// under the premise it falsifies, and the one-refusal history runs
    /// every step with no failure. Each falsifier declares its premise,
    /// and no history of `SEEDED` shares a name with a listed one.
    #[test]
    fn the_seeded_lw_histories_end_as_declared_under_pinned_roots() {
        for history in SEEDED {
            assert!(
                super::super::every().all(|listed| listed.name != history.name),
                "{} is listed",
                history.name
            );
            let falsifier = matches!(history.expect, Expect::Unsuccessful(_));
            assert_eq!(falsifier, !history.premise.is_empty(), "{}", history.name);
            for root in ROOTS {
                assert_eq!(
                    run_end(history, root),
                    (End::Done, history.expect.failure()),
                    "{} at {root}",
                    history.name
                );
            }
        }
    }
}
