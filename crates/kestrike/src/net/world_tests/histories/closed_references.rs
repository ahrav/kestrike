//! A closed owner still takes back the transmit references its device finished reading, so no
//! custody domain keeps one after its holds end.
//!
//! Property: no custody domain keeps a reference after its proof. The rule this file judges is the one
//! `released_in_domain` of histories.rs fails with.
//!
//! Both histories publish a three-fragment object, start a GET of it whose first DATA is sent while its later
//! reads stay held, and withhold every transmit reference the links' devices finished reading. The device
//! holds end first; once the device holds no command and no datagram that carries a reference is queued, the
//! transmit hold ends, and each withheld reference becomes returnable to its sender.
//!
//! - `cl2-get-references-after-close`: the owner closes while the DATA is in flight. A
//!   closed owner sends nothing, so its polls are all that can take the references back.
//! - `cl2-get-references-while-open`: the owner stays open and its GET goes on.
//!
//! The judging step counts owner polls and never waits on the clock. It runs once the links hold nothing but
//! references that are returnable to the owner: no command on the device, nothing queued, nothing withheld,
//! nothing returnable to a client. From then on only an owner poll changes what the links hold, unless the
//! owner sends again. The step passes when the links hold nothing. When a returnable reference is left, it
//! notes the owner's sent frames and polls, stays, and judges after two more polls with no further send: a
//! reference still held then is the rule's violation.

use std::cell::Cell;

use super::*;

/// The end of each link the owner sends from.
const OWNER_END: usize = 1;

const LEFT_OPEN: &str = "owner left open with DATA in flight";
const OPEN_RETAINED: &str = "the holds kept DATA under an open owner";
const NIC_RELEASED: &str = "transmit hold released with the device idle";

thread_local! {
    /// The owner's sent frames and polls when the judging step first found the links holding only
    /// references returnable to the owner. Each run's first step clears it.
    static WATCH: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
}

fn arm_watched(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    WATCH.with(|watch| watch.set(None));
    arm_nic(world, now)
}

/// References the links hold that the owner's next `reclaim` returns.
fn owner_returnable(world: &Mixed<'_, '_, '_>) -> usize {
    world
        .scene
        .nets
        .iter()
        .map(|net| net.borrow().reclaimable(OWNER_END))
        .sum()
}

/// The device holds no command, and the links hold no reference an owner poll cannot take back: none of a
/// queued datagram, none withheld and none returnable to a client.
fn only_owner_returns_left(world: &Mixed<'_, '_, '_>) -> bool {
    world.scene.control.outstanding() == 0 && nic_held(world) == owner_returnable(world)
}

/// The device holds no command and every reference the links hold is withheld, so ending the transmit hold
/// leaves nothing that needs the clock to move.
fn device_idle_and_delivered(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.control.outstanding() == 0 && nic_held(world) as u64 == withheld(world)
}

fn release_transmit(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_nic = false;
    mark(world, NIC_RELEASED)
}

/// The owner's sent frames and polls now.
fn owner_progress(world: &Mixed<'_, '_, '_>) -> (u64, u64) {
    (world.scene.owner.report().sent, world.owner_polls)
}

/// Whether the owner polled twice, and sent nothing, since the judging step noted `watch`.
fn polled_twice_since(world: &Mixed<'_, '_, '_>, watch: Option<(u64, u64)>) -> Option<bool> {
    let (sent, polls) = owner_progress(world);
    watch
        .filter(|&(noted, _)| noted == sent)
        .map(|(_, noted)| polls >= noted + 2)
}

fn returns_due(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    only_owner_returns_left(world)
        && (owner_returnable(world) == 0
            || polled_twice_since(world, WATCH.with(Cell::get)) != Some(false))
}

/// Judges with `released_in_domain` once the owner had two polls to take back what only it can.
fn returned(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if !only_owner_returns_left(world) {
        return STAY;
    }
    if owner_returnable(world) != 0 {
        match polled_twice_since(world, WATCH.with(Cell::get)) {
            Some(true) => {}
            Some(false) => return STAY,
            None => {
                WATCH.with(|watch| watch.set(Some(owner_progress(world))));
                return STAY;
            }
        }
    }
    released_in_domain(world, now)
}

/// The sibling's step in place of the close: it notes what the close notes and leaves the owner open.
fn leave_open(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.polls_at_close = world.owner_polls;
    world.history.refs = withheld(world);
    mark(world, LEFT_OPEN)
}

/// The sibling's premise after an owner poll: every withheld reference is still held and every held read
/// is still pending.
fn open_retained(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let retained = withheld(world) >= world.history.refs && commands_pending(world);
    premised(world, retained, OPEN_RETAINED)
}

const CLOSED: [Step; 10] = [
    step("arm", always, arm_watched),
    step("fill-long", always, fill_long),
    step("publish-long", fill_written, publish_fill),
    step("long-get", active_put, long_get),
    step("close", data_withheld, close_owner),
    step("close-retained", owner_polled, close_retained),
    step("release-device", always, release_device),
    step(
        "release-transmit",
        device_idle_and_delivered,
        release_transmit,
    ),
    step("returned", returns_due, returned),
    JUDGE,
];

const OPEN: [Step; 10] = replaced(
    replaced(
        CLOSED,
        "close",
        step("leave-open", data_withheld, leave_open),
    ),
    "close-retained",
    step("open-retained", owner_polled, open_retained),
);

const CLOSED_WITNESSES: &[&str] = &[
    "replacement published",
    "owner closed with DATA in flight",
    "close retained DATA and stopped sends",
    NIC_RELEASED,
    "each custody domain released after its proof",
];

const OPEN_WITNESSES: &[&str] = &[
    "replacement published",
    LEFT_OPEN,
    OPEN_RETAINED,
    NIC_RELEASED,
    "each custody domain released after its proof",
];

/// The open sibling's one check is the return of every reference, a check of `Obligation::Resources`. The
/// Custody check of what a close keeps belongs to the closed history.
const OPEN_JUDGED: &[Obligation] = &[Obligation::Resources];

pub(super) const CLOSED_REFERENCES: [History; 2] = [
    history(
        "cl2-get-references-after-close",
        &CLOSED,
        CLOSED_WITNESSES,
        CUSTODY_RESOURCES,
        Expect::Pass,
    ),
    history(
        "cl2-get-references-while-open",
        &OPEN,
        OPEN_WITNESSES,
        OPEN_JUDGED,
        Expect::Pass,
    ),
];
