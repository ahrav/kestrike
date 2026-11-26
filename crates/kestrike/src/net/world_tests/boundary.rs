//! Scenarios that walk the mixed world up to a named resource boundary by
//! real increments, and a long mixed GET/PUT run.
//!
//! Each boundary scenario starts below its boundary, or at a declared
//! near-boundary start, and reaches it through the world's own turns:
//!
//! - `boundary-collision` hashes a key nothing was published under to the
//!   resident object's word, and the GET client reads that key once an
//!   upload published.
//! - `boundary-fragmentation` publishes a local object, then the upload
//!   after it; the local object's lease is released and the owner's
//!   maintenance expires it at its deadline, so pressure reserves fills of
//!   the same length in the hole it left. It runs over the scaled geometry,
//!   whose sixteen slots give the free-run index two entries, one for the
//!   hole and one for the tail run.
//! - `boundary-mixed-size` uploads six fragments, more than the uploading
//!   client's four source slots and the owner's PUT window, beside a GET of
//!   the 1000-byte resident object and a GET of the upload.
//! - `boundary-real-counter` drops every PUT BEGIN on the uploading
//!   client's link, so its BEGIN sends count up past the client's resend
//!   limit and the upload ends `Unknown`, beside a GET of the resident
//!   object.

use crate::sim::action::{ActionKind, Profile};

use super::{
    FRAGMENT_LEN, Mixed, Plan, Plant, QUIET, UPLOAD, UPLOAD_PLAN, exactly_read, get_decided,
};
use crate::net::upload::UploadOutcome;

#[cfg(test)]
mod tests;

/// The six-fragment object the mixed-size scenario uploads, the last
/// fragment short.
pub(super) const LARGE_LEN: u32 = 6 * FRAGMENT_LEN - 100;

/// Drain turns the long run takes once its goal holds.
pub(super) const LONG_DRAIN: u32 = 1_000;

fn profile(name: &'static str, root: u64, extra: &[ActionKind]) -> Profile {
    Profile {
        name,
        declared: [UPLOAD.as_slice(), extra].concat(),
        root,
    }
}

/// Both GETs decided and the upload published, the GET client's read
/// exact.
fn both_read(world: &Mixed<'_, '_, '_>) -> bool {
    exactly_read(world)
        && world.gets[0]
            .as_ref()
            .is_some_and(|get| get.outcome.is_some())
}

/// The upload published and the GET client's read decided.
fn published_then_decided(world: &Mixed<'_, '_, '_>) -> bool {
    world.published() && get_decided(world)
}

/// The upload published, the GET client read it exactly, and pressure
/// holds its fills.
fn fragmented(world: &Mixed<'_, '_, '_>) -> bool {
    exactly_read(world) && matches!(world.pressure, super::Pressure::Holding(_))
}

/// The upload's outcome was collected `Unknown` and the GET client's read
/// decided.
fn unknown_then_decided(world: &Mixed<'_, '_, '_>) -> bool {
    get_decided(world)
        && world
            .put
            .as_ref()
            .is_some_and(|put| put.outcome == Some(UploadOutcome::Unknown))
}

const TINY_STEPS: [super::Step; 4] = [
    super::Step {
        name: "reserved-get",
        ready: |world, _| world.put.as_ref().is_some_and(|put| put.prepared) && world.uploading(),
        run: |world, now| {
            world.history.hold_nic = true;
            match world.get(0, now) {
                super::REFUSED => super::histories::STAY,
                applied => applied,
            }
        },
    },
    super::Step {
        name: "full-share-get",
        ready: |world, _| world.scene.owner.census().live() == 2,
        run: |world, now| {
            let first = world.gets[0].take();
            let outcome = world.get(0, now);
            if outcome == super::REFUSED {
                world.gets[0] = first;
                return super::histories::STAY;
            }
            world.overlapping_get = first;
            outcome
        },
    },
    super::Step {
        name: "collect-pressure-get",
        ready: |world, _| {
            world.gets[0]
                .as_ref()
                .is_some_and(|get| world.scene.clients[0].outcome(get.id).is_some())
        },
        run: |world, _| {
            let outcome = world.read(0);
            world.gets[0] = world.overlapping_get.take();
            world.history.hold_nic = false;
            outcome
        },
    },
    super::Step {
        name: "collect-reserved-get",
        ready: |world, _| {
            world.gets[0]
                .as_ref()
                .is_some_and(|get| world.scene.clients[0].outcome(get.id).is_some())
        },
        run: |world, _| world.read(0),
    },
];

fn tiny_plan() -> Plan {
    Plan {
        gets: [2, 1],
        share: Some(2),
        get_during_upload: true,
        withheld_tx: true,
        script: &TINY_STEPS,
        ..UPLOAD_PLAN
    }
}

/// The plan of the collision scenario, its fingerprint forged or not.
pub(super) fn collision_plan(collide: bool) -> Plan {
    Plan {
        read_stranger: true,
        collide,
        ..UPLOAD_PLAN
    }
}

/// The plan of the mixed-size scenario with `commands` write commands
/// per owner turn for its PUTs, the owner's own count when `None`.
pub(super) fn mixed_size_plan(commands: Option<usize>) -> Plan {
    Plan {
        gets: [1, 1],
        get_during_upload: true,
        object_len: LARGE_LEN,
        source_bytes: LARGE_LEN,
        put_commands: commands,
        ..UPLOAD_PLAN
    }
}

/// The boundary scenario `name` names.
pub(super) fn named(name: &str, root: u64) -> Option<super::bundle::Scenario> {
    let scenario: super::bundle::Scenario = match name {
        "boundary-tiny" => (
            profile("tiny request share", root, &[]),
            tiny_plan(),
            both_read,
        ),
        "boundary-collision" => (
            profile("fingerprint collision", root, &[]),
            collision_plan(true),
            published_then_decided,
        ),
        "boundary-fragmentation" => (
            profile(
                "fills in a freed extent",
                root,
                &[
                    ActionKind::Fill,
                    ActionKind::Receive,
                    ActionKind::Publish,
                    ActionKind::Release,
                    ActionKind::Pressure,
                ],
            ),
            Plan {
                fragmenting: true,
                geometry: super::Geometry::Scaled,
                ..UPLOAD_PLAN
            },
            fragmented,
        ),
        "boundary-mixed-size" => (
            profile("mixed object sizes", root, &[]),
            mixed_size_plan(None),
            both_read,
        ),
        "boundary-real-counter" => (
            Profile {
                name: "upload resends to their limit",
                declared: vec![
                    ActionKind::Get,
                    ActionKind::Read,
                    ActionKind::PutInvoke,
                    ActionKind::PutOutcome,
                ],
                root,
            },
            Plan {
                gets: [0, 1],
                puts: 1,
                read_resident: true,
                drop_begin: true,
                ..QUIET
            },
            unknown_then_decided,
        ),
        _ => return None,
    };
    Some(scenario)
}

/// Every planned upload published and every planned GET read: both
/// clients read the last upload's bytes exactly.
fn long_goal(world: &Mixed<'_, '_, '_>) -> bool {
    world.plan.spent()
        && exactly_read(world)
        && world.gets[0]
            .as_ref()
            .is_some_and(|get| get.bytes == world.read.1)
}

/// The long run's planted form stops at its first failure or its goal.
fn long_planted_goal(world: &Mixed<'_, '_, '_>) -> bool {
    world.first.get().is_some() || long_goal(world)
}

/// The long mixed run: two uploads of one key, each publishing in turn,
/// with a deferring supplier over faulty links, three reads by the GET
/// client and one by the uploading client, each after a publication, and
/// [`LONG_DRAIN`] drain turns. Its planted form changes a payload byte of
/// the first published record.
pub(super) fn long(planted: bool, root: u64) -> super::bundle::Scenario {
    let profile = profile("long mixed GET and PUT", root, &[ActionKind::DeferSupply]);
    let plan = Plan {
        gets: [1, 3],
        puts: 2,
        withhold: 1,
        link_faults: true,
        drain: LONG_DRAIN,
        plant: if planted {
            Plant::PublishedByte
        } else {
            Plant::None
        },
        ..UPLOAD_PLAN
    };
    let goal = if planted {
        long_planted_goal
    } else {
        long_goal
    };
    (profile, plan, goal)
}
