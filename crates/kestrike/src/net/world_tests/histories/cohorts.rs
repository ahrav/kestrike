use super::*;

use super::super::super::frame::{Header, Kind};
use super::incidents::{
    displace, displaced, fill_c, judge_pressured, mark_displaced, mark_old_drained, new_decided,
    new_exact, new_get, note_epoch, old_drained, old_frames, old_frames_refused, old_held,
    old_kept, old_refused, over_share_decided, over_share_timed,
};

const LABEL_A: Label = Label(1);

fn identity(world: &mut Mixed<'_, '_, '_>, actor: usize, id: RequestId, label: Label) -> Identity {
    Identity {
        episode: world.profile.name,
        actor,
        attempt: attempt(world, actor, id),
        label,
        token: None,
        incarnation: world.scene.clients[actor].session_epoch(),
    }
}

fn record(
    world: &mut Mixed<'_, '_, '_>,
    role: Role,
    name: &'static str,
    identity: Identity,
) -> u64 {
    let at = world.history.events.len();
    world.history.events.push(Event {
        role,
        name,
        identity,
        at,
    });
    mark(world, name)
}

fn old_identity(world: &mut Mixed<'_, '_, '_>) -> Identity {
    let id = world.gets[1].as_ref().expect("the old GET").id;
    identity(world, 1, id, LABEL_A)
}

fn held_token(world: &Mixed<'_, '_, '_>) -> Option<CommandToken> {
    world.history.held.first().copied()
}

fn held_old_identity(world: &mut Mixed<'_, '_, '_>) -> Identity {
    Identity {
        token: held_token(world),
        ..old_identity(world)
    }
}

const MIXED: &str = "a cohort's setup, effect and check named different identities";
const DISORDERED: &str = "a cohort's setup, effect and check ran out of order";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rejection {
    /// No event, or more than one, holds this name in its role.
    Missing(&'static str),
    Mixed,
    Disordered,
}

/// Judges `events` for the setup, effect and check `names` give, in role
/// order, and requires them recorded in that order. The effect carries the
/// setup's token, or none where the setup names none; the check names no
/// token or the effect's.
fn conjunction(events: &[Event], names: [&'static str; 3]) -> Result<(), Rejection> {
    let only = |role: Role, name: &'static str| {
        let mut matching = events
            .iter()
            .filter(|event| event.role == role && event.name == name);
        match (matching.next().copied(), matching.next()) {
            (Some(event), None) => Ok(event),
            _ => Err(Rejection::Missing(name)),
        }
    };
    let setup = only(Role::Injection, names[0])?;
    let effect = only(Role::Effect, names[1])?;
    let check = only(Role::Check, names[2])?;
    let same = |left: Identity, right: Identity| {
        Identity {
            token: None,
            ..left
        } == Identity {
            token: None,
            ..right
        }
    };
    let carried = setup.identity.token == effect.identity.token;
    let checked = check.identity.token.is_none() || check.identity.token == effect.identity.token;
    if !same(setup.identity, effect.identity)
        || !same(effect.identity, check.identity)
        || !carried
        || !checked
    {
        return Err(Rejection::Mixed);
    }
    if !(setup.at < effect.at && effect.at < check.at) {
        return Err(Rejection::Disordered);
    }
    Ok(())
}

pub(super) const CONJOINED: &str = "the cohort's setup, effect and check conjoined";

fn conjoin(world: &mut Mixed<'_, '_, '_>, names: [&'static str; 3]) -> u64 {
    match conjunction(&world.history.events, names) {
        Ok(()) => mark(world, CONJOINED),
        Err(Rejection::Missing(name)) => {
            world.first.record(Failure::Unsuccessful(name));
            0
        }
        Err(Rejection::Mixed) => fail(world, Obligation::History, MIXED),
        Err(Rejection::Disordered) => fail(world, Obligation::History, DISORDERED),
    }
}

fn c1_setup(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let identity = held_old_identity(world);
    record(world, Role::Injection, C1[0], identity)
}

fn c1_effect(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let identity = held_old_identity(world);
    record(world, Role::Effect, C1[1], identity)
}

fn c1_effect_reincarnated(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let identity = held_old_identity(world);
    let identity = Identity {
        incarnation: identity.incarnation.map(|epoch| epoch + 1),
        ..identity
    };
    record(world, Role::Effect, C1[1], identity)
}

fn c1_effect_other_token(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = held_token(world);
    let other = world
        .scene
        .control
        .events()
        .into_iter()
        .find_map(|event| match event {
            DiskEvent::Submitted(token, _) if Some(token) != held => Some(token),
            _ => None,
        });
    let identity = Identity {
        token: other,
        ..held_old_identity(world)
    };
    record(world, Role::Effect, C1[1], identity)
}

fn c1_effect_twice(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    c1_effect(world, now);
    c1_effect(world, now)
}

fn c1_released_then_effect(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    release_reads(world, now);
    c1_effect(world, now)
}

fn c1_setup_unrecorded(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, C1[0])
}

fn c1_effect_then_setup(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    c1_effect(world, now);
    c1_setup(world, now)
}

fn c1_cancel_then_release(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if !world.history.marks.contains(&"held read cancelled") {
        cancel_old(world, now);
        return STAY;
    }
    if !cancel_received(world, now) {
        return STAY;
    }
    release_reads(world, now)
}

/// A control's fresh GET, its wire request ID read while it is live.
fn c1_fresh_get_noted(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if fresh_get(world, now) == STAY {
        return STAY;
    }
    let id = *world.history.ids.last().expect("the fresh GET");
    attempt(world, 0, id);
    1
}

fn c1_effect_elsewhere(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = *world.history.ids.last().expect("the fresh GET");
    let identity = identity(world, 0, id, LABEL_A);
    record(world, Role::Effect, C1[1], identity)
}

const C1_ENDED_SHORT: &str = "the old right ended without its version";

fn c1_check(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    let get = world.gets[1].as_ref().expect("the old GET");
    let (outcome, bytes) = (get.outcome, get.bytes.clone());
    if !read_exact(outcome, &bytes, &version_a()) {
        return fail(world, Obligation::Bytes, C1_ENDED_SHORT);
    }
    let identity = old_identity(world);
    record(world, Role::Check, C1[2], identity)
}

fn c1_conjoin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    conjoin(world, C1)
}

const C1: [&str; 3] = [
    "C1 old right and its read held",
    "C1 replacement under the held right",
    "C1 old right returned its version",
];

const C1_STEPS: [Step; 17] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("setup", always, c1_setup),
    step("invalidate", always, invalidate),
    step("fresh-get", active_put, fresh_get),
    step("fresh-miss", fresh_decided, fresh_missed),
    step("fill-replacement", always, fill_b),
    step("publish-replacement", fill_written, publish_fill),
    step("effect", always, c1_effect),
    step("release-old-read", always, release_reads),
    step("check", old_decided, c1_check),
    step("release-nic", always, release_nic),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    step("conjoin", always, c1_conjoin),
    JUDGE,
];

const C1_MIXED: [Step; 17] = replaced(
    replaced(
        C1_STEPS,
        "fresh-get",
        step("fresh-get-noted", active_put, c1_fresh_get_noted),
    ),
    "effect",
    step("effect-elsewhere", always, c1_effect_elsewhere),
);

const C1_UNRECORDED: [Step; 17] = replaced(
    C1_STEPS,
    "setup",
    step("setup-unrecorded", always, c1_setup_unrecorded),
);

const C1_DUPLICATE: [Step; 17] = replaced(
    C1_STEPS,
    "effect",
    step("effect-twice", always, c1_effect_twice),
);

const C1_REINCARNATED: [Step; 17] = replaced(
    C1_STEPS,
    "effect",
    step("effect-reincarnated", always, c1_effect_reincarnated),
);

const C1_OTHER_TOKEN: [Step; 17] = replaced(
    C1_STEPS,
    "effect",
    step("effect-other-token", always, c1_effect_other_token),
);

const C1_AFTER_RELEASE: [Step; 17] = replaced(
    replaced(
        C1_STEPS,
        "effect",
        step("effect-deferred", always, removed_step),
    ),
    "release-old-read",
    step("release-then-effect", always, c1_released_then_effect),
);

const C1_OLD_CANCELLED: [Step; 17] = replaced(
    C1_STEPS,
    "release-old-read",
    step("cancel-then-release", always, c1_cancel_then_release),
);

const C1_OUT_OF_ORDER: [Step; 17] = replaced(
    replaced(
        C1_STEPS,
        "effect",
        step("effect-early", always, removed_step),
    ),
    "setup",
    step("effect-then-setup", always, c1_effect_then_setup),
);

const C1_WITNESSES: &[&str] = &[
    "C1 old right and its read held",
    "invalidation acknowledged",
    "fresh GET missed",
    "C1 replacement under the held right",
    "C1 old right returned its version",
    "qualified exact read",
    CONJOINED,
];

fn c2_setup(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let identity = held_old_identity(world);
    cancel_old(world, now);
    record(world, Role::Injection, C2[0], identity)
}

fn c2_effect(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let identity = held_old_identity(world);
    release_reads(world, now);
    record(world, Role::Effect, C2[1], identity)
}

fn c2_check(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let identity = old_identity(world);
    if successor_get(world, now) == STAY {
        return STAY;
    }
    if !world
        .history
        .marks
        .contains(&"successor reused the slot at a higher generation")
    {
        return 1;
    }
    record(world, Role::Check, C2[2], identity)
}

fn c2_conjoin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    conjoin(world, C2)
}

const C2: [&str; 3] = [
    "C2 cancel with its read held",
    "C2 cancelled read released for its late terminal",
    "C2 successor took a fresh identity",
];

const C2_STEPS: [Step; 11] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("setup", always, c2_setup),
    step("cancel-kept", cancel_received, cancel_kept),
    step("effect", always, c2_effect),
    step("drained", drained, mark_drained),
    step("check", active_get, c2_check),
    step("successor-read", successor_decided, successor_get_exact),
    step("conjoin", always, c2_conjoin),
    JUDGE,
];

const C2_WITNESSES: &[&str] = &[
    "C2 cancel with its read held",
    "cancel kept custody",
    "C2 cancelled read released for its late terminal",
    "the cancelled request drained after its terminal",
    "C2 successor took a fresh identity",
    "qualified exact read",
    CONJOINED,
];

fn third_identity(world: &mut Mixed<'_, '_, '_>) -> Identity {
    identity(world, 1, world.history.ids[2], LABEL_A)
}

fn c3_setup(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if over_share_timed(world, now) == STAY {
        return STAY;
    }
    let identity = third_identity(world);
    record(world, Role::Injection, C3[0], identity)
}

fn c3_effect(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let identity = third_identity(world);
    if judge_pressured(world, now) == 0 {
        return 0;
    }
    record(world, Role::Effect, C3[1], identity);
    record(world, Role::Check, C3[2], identity)
}

fn c3_conjoin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    conjoin(world, C3)
}

const C3: [&str; 3] = [
    "C3 GET past the share",
    "C3 typed pressure",
    "C3 pressure kept its one deadline",
];

const C3_STEPS: [Step; 11] = [
    step("arm", always, arm),
    step("saturate", active_get, saturate),
    step("reads-held", reads_held, |world, _| {
        mark(world, "saturating reads held")
    }),
    step("setup", always, c3_setup),
    step("effect", over_share_decided, c3_effect),
    step("conjoin", always, c3_conjoin),
    step("peer-get", active_put, peer_get),
    step("peer-read", peer_decided_or_late, peer_exact),
    step("release", always, release_everything),
    step("healed", saturated_drained, saturated_exact),
    JUDGE,
];

const C3_WITNESSES: &[&str] = &[
    "share saturated",
    "saturating reads held",
    "C3 GET past the share",
    "C3 typed pressure",
    "C3 pressure kept its one deadline",
    "the GET past the share ended typed within its deadline",
    CONJOINED,
    "eligible peer progressed",
    "qualified exact read",
];

fn long_identity(world: &mut Mixed<'_, '_, '_>) -> Identity {
    let id = *world.history.ids.last().expect("the long GET");
    identity(world, 0, id, LABEL_B)
}

fn c4_setup(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let identity = Identity {
        token: held_token(world),
        ..long_identity(world)
    };
    record(world, Role::Injection, C4[0], identity)
}

fn c4_effect(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let identity = Identity {
        token: held_token(world),
        ..long_identity(world)
    };
    close_owner(world, now);
    record(world, Role::Effect, C4[1], identity)
}

fn c4_check(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let identity = long_identity(world);
    if close_retained(world, now) == 0 {
        return 0;
    }
    record(world, Role::Check, C4[2], identity)
}

/// A control: the close drops the held read, the device posting its
/// completion at the close.
fn c4_effect_dropping(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let identity = Identity {
        token: held_token(world),
        ..long_identity(world)
    };
    close_dropping_reads(world, now);
    record(world, Role::Effect, C4[1], identity)
}

fn c4_conjoin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    conjoin(world, C4)
}

const C4: [&str; 3] = [
    "C4 accepted TX prefix held",
    "C4 close with DATA held",
    "C4 close retained the accepted references",
];

const C4_STEPS: [Step; 11] = [
    step("arm", always, arm_nic),
    step("fill-long", always, fill_long),
    step("publish-long", fill_written, publish_fill),
    step("long-get", active_put, long_get),
    step("setup", data_withheld, c4_setup),
    step("effect", always, c4_effect),
    step("check", owner_polled, c4_check),
    step("release", always, release_everything),
    step("returned", released_or_late, released_in_domain),
    step("conjoin", always, c4_conjoin),
    JUDGE,
];

const C4_DROPPING: [Step; 11] = replaced(
    C4_STEPS,
    "effect",
    step("effect-dropping", always, c4_effect_dropping),
);

const C4_WITNESSES: &[&str] = &[
    "replacement published",
    "C4 accepted TX prefix held",
    "C4 close with DATA held",
    "close retained DATA and stopped sends",
    "C4 close retained the accepted references",
    "each custody domain released after its proof",
    CONJOINED,
];

fn c6_setup(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let identity = held_old_identity(world);
    record(world, Role::Injection, C6[0], identity)
}

fn c6_effect(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !super::super::bundle::change_published(&world.scene, 1) {
        return STAY;
    }
    let identity = held_old_identity(world);
    record(world, Role::Effect, C6[1], identity)
}

/// A damaged read's end: an integrity failure whose delivered bytes are a
/// prefix of `version`.
fn damaged_prefix(outcome: Option<Outcome>, bytes: &[u8], version: &[u8]) -> bool {
    outcome == Some(Outcome::Failed(Status::IntegrityError)) && version.starts_with(bytes)
}

fn c6_check(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    let get = world.gets[1].as_ref().expect("the old GET");
    let (outcome, bytes) = (get.outcome, get.bytes.clone());
    let identity = old_identity(world);
    if !damaged_prefix(outcome, &bytes, &version_a()) {
        return fail(
            world,
            Obligation::Bytes,
            "a damaged read ended other than with a verified prefix and a typed failure",
        );
    }
    record(world, Role::Check, C6[2], identity)
}

fn c6_conjoin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    conjoin(world, C6)
}

const C6: [&str; 3] = [
    "C6 old right and its read held",
    "C6 media damaged under the held read",
    "C6 damaged read ended with a verified prefix and a typed failure",
];

const C6_STEPS: [Step; 13] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("setup", always, c6_setup),
    step("effect", always, c6_effect),
    step("fill-replacement", always, fill_b),
    step("publish-replacement", fill_written, publish_fill),
    step("release-old-read", always, release_reads),
    step("check", old_decided, c6_check),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    step("conjoin", always, c6_conjoin),
    JUDGE,
];

const C6_WITNESSES: &[&str] = &[
    "C6 old right and its read held",
    "C6 media damaged under the held read",
    "replacement published",
    "C6 damaged read ended with a verified prefix and a typed failure",
    "qualified exact read",
    CONJOINED,
];

fn wrong_operation(world: &Mixed<'_, '_, '_>) -> u64 {
    world.scene.owner.report().wrong_operation
}

pub(super) fn s19_concurrent_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let applied = match world.get(0, now) {
        super::super::REFUSED => return STAY,
        applied => applied,
    };
    let id = world.gets[0].as_ref().expect("the concurrent GET").id;
    attempt(world, 0, id);
    applied
}

/// Keeps the header of client 1's GET of key 1 when it is the newest
/// datagram in flight toward the owner, and reports whether it was.
pub(super) fn learn_get(world: &mut Mixed<'_, '_, '_>) -> bool {
    let crc = crate::storage::Crc32c::detect();
    let get = world.scene.nets[1]
        .borrow()
        .peek(1)
        .and_then(|bytes| {
            super::super::super::frame::parse(crc, &bytes, false)
                .ok()
                .map(|frame| frame.header())
        })
        .filter(|header| header.kind == Kind::Get && header.key == key(1));
    if get.is_some() {
        world.history.learned = get;
    }
    get.is_some()
}

pub(super) fn s19_learn(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !learn_get(world) {
        return STAY;
    }
    mark(world, "S3-D-19 the GET's header learned")
}

/// The premises of a frame forged at the live named GET, each named in the
/// error: its wire slot is bound, and the owner's census holds only the
/// history's requests and the live refresh GETs.
pub(super) fn s19_formed(world: &Mixed<'_, '_, '_>) -> Result<(), &'static str> {
    let before = counters(world);
    let issued = world.gets.iter().flatten().count()
        + world.history.ids.len()
        + usize::from(world.history.put.is_some())
        + usize::from(world.history.peer.is_some());
    let refreshed = refresh_live(world);
    s19_precondition(before, world.scene.owner.census(), issued as u32, refreshed)
}

fn s19_setup(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if let Err(reason) = s19_formed(world) {
        world.first.record(Failure::Unsuccessful(reason));
        return 0;
    }
    S19_CONCURRENT_WITNESSED.set(false);
    let get = world.history.learned.expect("the GET's header");
    let forged = forge(world, Kind::PutCancel, get.sequence + 1);
    let identity = Identity {
        attempt: forged.request,
        ..old_identity(world)
    };
    record(world, Role::Injection, S19[0], identity)
}

fn refresh_live(world: &Mixed<'_, '_, '_>) -> u32 {
    (0..world.scene.clients.len())
        .filter(|&peer| live_at_owner(world, peer as u16, world.scene.template(peer).request))
        .count() as u32
}

pub(super) fn live_at_owner(world: &Mixed<'_, '_, '_>, peer: u16, wire: u64) -> bool {
    let wire = RequestId::from_wire(wire);
    world
        .scene
        .owner
        .request_slot(PeerId(peer), wire.slot())
        .is_some_and(|row| row.watermark == Some(wire.generation()) && row.active.is_some())
}

thread_local! {
    static S19_CONCURRENT_WITNESSED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn s19_precondition(
    before: Counters,
    census: super::super::super::requests::RequestCensus,
    issued: u32,
    refreshed: u32,
) -> Result<(), &'static str> {
    if before.active.is_none() {
        return Err("the named GET's wire slot was active at setup");
    }
    if census.retired != 0 || census.live() != issued + refreshed || census.draining > refreshed {
        return Err("the setup census held only the history's requests and live refresh GETs");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Counters {
    pub(super) wrong_operation: u64,
    pub(super) watermark: Option<u64>,
    pub(super) active: Option<RequestId>,
    pub(super) cached: Option<(u64, u64, super::super::super::served::Outcome)>,
    pub(super) refused: Option<u64>,
}

pub(super) fn counters(world: &Mixed<'_, '_, '_>) -> Counters {
    let get = world.history.learned.expect("the GET's header");
    let row = world
        .scene
        .owner
        .request_slot(PeerId(1), RequestId::from_wire(get.request).slot())
        .unwrap_or_default();
    Counters {
        wrong_operation: wrong_operation(world),
        watermark: row.watermark,
        active: row.active,
        cached: row
            .cached
            .map(|row| (row.epoch, row.expires_us, row.outcome)),
        refused: row.refused,
    }
}

pub(super) fn forge(world: &mut Mixed<'_, '_, '_>, kind: Kind, sequence: u64) -> Header {
    let get = world.history.learned.expect("the GET's header");
    world.history.forged = Some(counters(world));
    let forged = Header { sequence, ..get };
    let (frame, _) = super::super::super::frame_tests::put_frame(kind, &forged);
    world.scene.inject(1, &frame);
    // Advancing the client's send sequence prevents reuse of the injected
    // frame's sequence number.
    world.scene.clients[1]
        .sessions_mut()
        .set_send(PeerId(0), forged.sequence + 1);
    forged
}

pub(super) fn s19_counted(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .forged
        .is_some_and(|before| wrong_operation(world) > before.wrong_operation)
}

fn s19_effect(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let identity = old_identity(world);
    record(world, Role::Effect, S19[1], identity)
}

fn s19_check(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let after = counters(world);
    judge_s19(world, after)
}

/// Oracle-sensitivity control: the owner is correct; the mutation alters the named row's snapshot.
fn s19_mutated(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let after = counters(world);
    judge_s19(
        world,
        Counters {
            active: None,
            ..after
        },
    )
}

/// Whether `after` is `before` with the wrong-operation counter raised by
/// `counted` and the named slot's row as it was.
pub(super) fn counted_only(before: Counters, after: Counters, counted: u64) -> bool {
    after
        == Counters {
            wrong_operation: before.wrong_operation + counted,
            ..before
        }
}

fn counter_only(before: Counters, after: Counters) -> bool {
    counted_only(before, after, 1)
}

pub(crate) const MOVED_MORE: &str = "a PUT frame naming a GET changed more than its counter";

pub(super) fn judge_forged(world: &mut Mixed<'_, '_, '_>, after: Counters) -> bool {
    let only = world
        .history
        .forged
        .is_some_and(|before| counter_only(before, after));
    if !only {
        fail(world, Obligation::Contain, MOVED_MORE);
    }
    only
}

const S19_CONCURRENT: &str = "S3-D-19 a concurrent GET stayed live through the check";

fn judge_s19(world: &mut Mixed<'_, '_, '_>, after: Counters) -> u64 {
    let id = world.gets[0].as_ref().expect("the concurrent GET").id;
    let wire = attempt(world, 0, id);
    if !live_at_owner(world, 0, wire) {
        world.first.record(Failure::Unsuccessful(
            "the concurrent GET was live at the check",
        ));
        return 0;
    }
    mark(world, S19_CONCURRENT);
    S19_CONCURRENT_WITNESSED.set(true);
    let only = judge_forged(world, after);
    let identity = old_identity(world);
    if !only {
        return 0;
    }
    record(world, Role::Check, S19[2], identity)
}

pub(super) fn get_released(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    let census = world.scene.owner.peer_census(PeerId(1));
    census.active + census.draining == 0
}

const S19_RELEASED: &str = "S3-D-19 GET retained after release";

fn s19_retained(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if get_released(world, now) {
        mark(world, S19_RELEASED);
    }
    let get = world.history.learned.expect("the GET's header");
    forge(world, Kind::PutBegin, get.sequence + 100);
    mark(world, "S3-D-19 a PUT BEGIN named the GET's retained row")
}

pub(super) const S19_RETAINED_CHECKED: &str =
    "S3-D-19 the retained row's PUT moved only its counter";

pub(super) fn s19_retained_checked(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let after = counters(world);
    if !judge_forged(world, after) {
        return 0;
    }
    mark(world, S19_RETAINED_CHECKED)
}

pub(super) fn read_exact(outcome: Option<Outcome>, bytes: &[u8], expected: &[u8]) -> bool {
    outcome == Some(Outcome::Complete) && bytes == expected
}

pub(super) const S19_READ: &str = "S3-D-19 the named GET read its exact version";

pub(super) fn s19_read(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    let get = world.gets[1].as_ref().expect("the old GET");
    let (outcome, bytes) = (get.outcome, get.bytes.clone());
    if !read_exact(outcome, &bytes, &version_a()) {
        return fail(
            world,
            Obligation::Bytes,
            "a GET a PUT frame named ended other than with its exact version",
        );
    }
    mark(world, S19_READ)
}

pub(super) fn concurrent_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.gets[0]
        .as_ref()
        .is_some_and(|get| world.scene.clients[0].outcome(get.id).is_some())
}

pub(super) fn s19_concurrent_read(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(0);
    let get = world.gets[0].as_ref().expect("the concurrent GET");
    if !read_exact(get.outcome, &get.bytes, &version_a()) {
        return fail(
            world,
            Obligation::Bytes,
            "the concurrent GET ended other than with its exact version",
        );
    }
    mark(world, S19_CONCURRENT_READ)
}

pub(super) const S19_CONCURRENT_READ: &str = "S3-D-19 the concurrent GET read its exact version";

fn s19_conjoin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    conjoin(world, S19)
}

pub(super) fn get_sent(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.nets[1].borrow().pending(1) > 0
}

pub(super) const S19: [&str; 3] = [
    "S3-D-19 PUT CANCEL naming the live GET",
    "S3-D-19 wrong operation counted",
    "S3-D-19 only the counter moved",
];

const S19_STEPS: [Step; 16] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("learn", get_sent, s19_learn),
    step("concurrent-get", active_put, s19_concurrent_get),
    step("old-read-held", reads_held, mark_read_held),
    step("setup", always, s19_setup),
    step("effect", s19_counted, s19_effect),
    step("check", always, s19_check),
    step("release-old-read", always, release_reads),
    step("old-right", old_decided, s19_read),
    step("concurrent-right", concurrent_decided, s19_concurrent_read),
    step("conjoin", always, s19_conjoin),
    step("release-nic", always, release_nic),
    step("retained", get_released, s19_retained),
    step("retained-checked", s19_counted, s19_retained_checked),
    JUDGE,
];

const S19_LIVE: [Step; 16] = replaced(
    replaced(
        S19_STEPS,
        "release-nic",
        step("nic-kept", always, removed_step),
    ),
    "retained",
    step("retained-live", always, s19_retained),
);

const S19_MUTATED: [Step; 16] = replaced(
    S19_STEPS,
    "check",
    step("check-mutated", always, s19_mutated),
);

/// GET budgets of the S3-D-19 scripts: the first client's concurrent GET
/// and the second client's named GET.
const S19_GETS: [u32; 2] = [1, 1];

const S19_WITNESSES: &[&str] = &[
    "S3-D-19 PUT CANCEL naming the live GET",
    "S3-D-19 wrong operation counted",
    "S3-D-19 only the counter moved",
    S19_CONCURRENT,
    S19_READ,
    S19_CONCURRENT_READ,
    CONJOINED,
    S19_RELEASED,
    "S3-D-19 a PUT BEGIN named the GET's retained row",
    S19_RETAINED_CHECKED,
];

fn displaced_identity(world: &mut Mixed<'_, '_, '_>) -> Identity {
    let attempt = attempt(world, 0, world.history.ids[0]);
    let old = world.scene.spare.as_ref().expect("the displaced client");
    Identity {
        episode: world.profile.name,
        actor: 0,
        attempt,
        label: LABEL_A,
        token: None,
        incarnation: old.session_epoch(),
    }
}

fn d19_setup(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.kept = u64::from(world.scene.owner.peer_census(PeerId(0)).active)
        + u64::from(world.scene.owner.peer_census(PeerId(0)).draining);
    let identity = Identity {
        token: held_token(world),
        ..identity(world, 0, world.history.ids[0], LABEL_A)
    };
    displace(world, now);
    record(world, Role::Injection, D19[0], identity)
}

fn d19_preserved(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let census = world.scene.owner.peer_census(PeerId(0));
    judge_d19(world, now, u64::from(census.active + census.draining))
}

/// A control: the old session's charges are read one lower, as a
/// displacement that dropped a live request would leave them.
fn d19_dropped(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let census = world.scene.owner.peer_census(PeerId(0));
    judge_d19(
        world,
        now,
        u64::from(census.active + census.draining).saturating_sub(1),
    )
}

fn judge_d19(world: &mut Mixed<'_, '_, '_>, now: u64, charged: u64) -> u64 {
    if charged < world.history.kept {
        return fail(
            world,
            Obligation::Custody,
            "a displacement dropped the old session's live charges",
        );
    }
    if old_kept(world, now) == 0 {
        return 0;
    }
    let identity = Identity {
        token: held_token(world),
        ..displaced_identity(world)
    };
    record(world, Role::Effect, D19[1], identity)
}

fn d19_check(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let identity = displaced_identity(world);
    record(world, Role::Check, D19[2], identity)
}

fn d19_successor(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if new_exact(world, now) == 0 {
        return 0;
    }
    let old = world.scene.spare.as_ref().expect("the displaced client");
    if world.scene.clients[0].session_epoch() == old.session_epoch() {
        return fail(
            world,
            Obligation::Contain,
            "a replacement client's GET ran under the displaced session",
        );
    }
    mark(
        world,
        "S3-D-19 the new client's GET completed under its own session",
    )
}

fn d19_conjoin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    conjoin(world, D19)
}

const D19: [&str; 3] = [
    "S3-D-19 a new boot displaced a session with a read held",
    "S3-D-19 the old session's charges stayed until its drain",
    "S3-D-19 the old session drained beside the new boot",
];

const D19_STEPS: [Step; 17] = [
    step("arm", always, arm),
    step("old-get", active_put, fresh_get),
    step("old-read-held", old_held, note_epoch),
    step("setup", always, d19_setup),
    step("displaced", displaced, mark_displaced),
    step("effect", always, d19_preserved),
    step("release-old-read", always, release_reads),
    step("old-drained", old_drained, mark_old_drained),
    step("check", always, d19_check),
    step("fill-successor", always, fill_c),
    step("publish-successor", fill_written, publish_fill),
    step("new-get", active_put, new_get),
    step("old-frames", always, old_frames),
    step("old-refused", old_frames_refused, old_refused),
    step("successor", new_decided, d19_successor),
    step("conjoin", always, d19_conjoin),
    JUDGE,
];

const D19_DROPPED: [Step; 17] = replaced(
    D19_STEPS,
    "effect",
    step("effect-dropped", always, d19_dropped),
);

const D19_WITNESSES: &[&str] = &[
    "old read held",
    "S3-D-19 a new boot displaced a session with a read held",
    "a replacement boot displaced the old session",
    "S3-D-19 the old session's charges stayed until its drain",
    "old work drained",
    "the displaced session's frames were refused",
    "S3-D-19 the old session drained beside the new boot",
    "the replacement read the visible version exactly",
    "S3-D-19 the new client's GET completed under its own session",
    CONJOINED,
];

pub(crate) const UNSUPPORTED: [(&str, &str); 2] = [
    (
        "C5",
        "the mixed world runs H6 with a peer owner beside the stopped one, but its steps record no cohort injection, effect or check events, so no cohort conjoins C5's cross-owner setup, effect and check",
    ),
    (
        "C7",
        "terminal counters need a board whose wire generation starts at its last value; the shared adapter builds every client's board before the run and does not yet start one at its last generation, and Releases::start_wire_at refuses a board in use",
    ),
];

const C1_JUDGED: &[Obligation] = &[Obligation::History, Obligation::Bytes];
const C2_JUDGED: &[Obligation] = &[
    Obligation::History,
    Obligation::Custody,
    Obligation::Resources,
];
const C3_JUDGED: &[Obligation] = &[
    Obligation::History,
    Obligation::Resources,
    Obligation::Progress,
];
const C4_JUDGED: &[Obligation] = &[
    Obligation::History,
    Obligation::Custody,
    Obligation::Resources,
];
const C6_JUDGED: &[Obligation] = &[Obligation::History, Obligation::Bytes];
const S19_JUDGED: &[Obligation] = &[Obligation::History, Obligation::Contain, Obligation::Bytes];
const D19_JUDGED: &[Obligation] = &[
    Obligation::History,
    Obligation::Custody,
    Obligation::Contain,
    Obligation::Bytes,
];

pub(super) const CHECKS: [(&str, Obligation); 7] = [
    (CONJOINED, Obligation::History),
    (C1[2], Obligation::Bytes),
    (C6[2], Obligation::Bytes),
    (S19[2], Obligation::Contain),
    (S19_RETAINED_CHECKED, Obligation::Contain),
    (S19_READ, Obligation::Bytes),
    (D19[1], Obligation::Custody),
];

pub(crate) const COHORTS: [History; 19] = [
    history("c1", &C1_STEPS, C1_WITNESSES, C1_JUDGED, Expect::Pass),
    control(
        history(
            "c1-mixed",
            &C1_MIXED,
            C1_WITNESSES,
            C1_JUDGED,
            Expect::Violation(Obligation::History, MIXED),
        ),
        &[
            "C1 old right and its read held",
            "C1 old right returned its version",
        ],
    ),
    control(
        history(
            "c1-reincarnated",
            &C1_REINCARNATED,
            C1_WITNESSES,
            C1_JUDGED,
            Expect::Violation(Obligation::History, MIXED),
        ),
        &[
            "C1 old right and its read held",
            "C1 old right returned its version",
        ],
    ),
    control(
        history(
            "c1-other-token",
            &C1_OTHER_TOKEN,
            C1_WITNESSES,
            C1_JUDGED,
            Expect::Violation(Obligation::History, MIXED),
        ),
        &[
            "C1 old right and its read held",
            "C1 old right returned its version",
        ],
    ),
    control(
        history(
            "c1-out-of-order",
            &C1_OUT_OF_ORDER,
            C1_WITNESSES,
            C1_JUDGED,
            Expect::Violation(Obligation::History, DISORDERED),
        ),
        &[
            "C1 old right and its read held",
            "C1 old right returned its version",
        ],
    ),
    history(
        "c1-unrecorded",
        &C1_UNRECORDED,
        C1_WITNESSES,
        C1_JUDGED,
        Expect::Unsuccessful(C1[0]),
    ),
    history(
        "c1-duplicate",
        &C1_DUPLICATE,
        C1_WITNESSES,
        C1_JUDGED,
        Expect::Unsuccessful(C1[1]),
    ),
    history("c2", &C2_STEPS, C2_WITNESSES, C2_JUDGED, Expect::Pass),
    history("c3", &C3_STEPS, C3_WITNESSES, C3_JUDGED, Expect::Pass),
    history("c4", &C4_STEPS, C4_WITNESSES, C4_JUDGED, Expect::Pass),
    control(
        history(
            "c4-close-dropping",
            &C4_DROPPING,
            C4_WITNESSES,
            C4_JUDGED,
            Expect::Violation(
                Obligation::Custody,
                "a close released DATA the device still held",
            ),
        ),
        &["C4 accepted TX prefix held", "C4 close with DATA held"],
    ),
    history("c6", &C6_STEPS, C6_WITNESSES, C6_JUDGED, Expect::Pass),
    getting(
        history(
            "s3-d-19",
            &S19_STEPS,
            S19_WITNESSES,
            S19_JUDGED,
            Expect::Pass,
        ),
        S19_GETS,
    ),
    control(
        getting(
            history(
                "s3-d-19-mutated",
                &S19_MUTATED,
                S19_WITNESSES,
                S19_JUDGED,
                Expect::Violation(Obligation::Contain, MOVED_MORE),
            ),
            S19_GETS,
        ),
        &[
            "S3-D-19 PUT CANCEL naming the live GET",
            "S3-D-19 wrong operation counted",
        ],
    ),
    getting(
        history(
            "s3-d-19-retained-live",
            &S19_LIVE,
            S19_WITNESSES,
            S19_JUDGED,
            Expect::Unsuccessful(S19_RELEASED),
        ),
        S19_GETS,
    ),
    history(
        "s3-d-19-displaced",
        &D19_STEPS,
        D19_WITNESSES,
        D19_JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "c1-old-cancelled",
            &C1_OLD_CANCELLED,
            C1_WITNESSES,
            C1_JUDGED,
            Expect::Violation(Obligation::Bytes, C1_ENDED_SHORT),
        ),
        &[
            "C1 old right and its read held",
            "C1 replacement under the held right",
        ],
    ),
    control(
        history(
            "c1-effect-after-release",
            &C1_AFTER_RELEASE,
            C1_WITNESSES,
            C1_JUDGED,
            Expect::Violation(Obligation::History, MIXED),
        ),
        &[
            "C1 old right and its read held",
            "C1 old right returned its version",
        ],
    ),
    control(
        history(
            "s3-d-19-displaced-dropped",
            &D19_DROPPED,
            D19_WITNESSES,
            D19_JUDGED,
            Expect::Violation(
                Obligation::Custody,
                "a displacement dropped the old session's live charges",
            ),
        ),
        &["S3-D-19 a new boot displaced a session with a read held"],
    ),
];

#[cfg(test)]
mod tests {
    use crate::sim::manifest::Manifest;
    use crate::sim::trace::{Outcome, PAYLOAD, Terminal, load};

    use super::super::super::bundle::{admit, failure_code, held_by, traced};
    use super::super::super::replay::{Replayed, replay};
    use super::super::{Expect, Role};
    use super::*;
    use super::{COHORTS, UNSUPPORTED};
    use crate::net::observe::Failure;

    fn manifest(name: &str) -> Manifest {
        let text = crate::sim::manifest_tests::sample(name, &"a".repeat(64), "x86_64-linux");
        Manifest::parse(&text).expect("a valid manifest")
    }

    fn ran(name: &str) -> (Outcome, Option<[u8; PAYLOAD]>, Vec<u8>) {
        let bytes = traced(admit(&manifest(name)).expect("admitted"), Vec::new()).sink;
        let loaded = load(&bytes, 1_000_000).expect("a loadable bundle");
        let Terminal::Complete { outcome, .. } = loaded.terminal else {
            panic!("{name}: {:?}", loaded.terminal);
        };
        (outcome, loaded.violation, bytes)
    }

    const S19_ROOTS: [u64; 3] = [
        4_898_386_983_627_183_704,
        1_033_726_202_903_346_643,
        10_451_216_379_200_822_465,
    ];

    fn concurrent_gone(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
        let id = world.gets[0].as_ref().expect("the concurrent GET").id;
        let wire = kept_wire(world, 0, id).expect("the concurrent GET's wire");
        !live_at_owner(world, 0, wire)
    }

    fn released_effect(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        release_reads(world, now);
        release_nic(world, now);
        s19_effect(world, now)
    }

    /// The mutated control's script with the reads and the NIC released at
    /// the effect, so the concurrent GET has left the owner when the check
    /// runs.
    const S19_MUTATED_UNWITNESSED: [Step; 16] = replaced(
        replaced(
            S19_MUTATED,
            "effect",
            step("effect", s19_counted, released_effect),
        ),
        "check-mutated",
        step("check-mutated", concurrent_gone, s19_mutated),
    );

    #[test]
    fn s3_d_19_mutated_ends_unsuccessful_when_the_concurrent_get_left_before_the_check() {
        let (profile, mut plan, goal) =
            super::super::named("s3-d-19-mutated", 3).expect("the mutated control");
        plan.script = &S19_MUTATED_UNWITNESSED;
        let chooser = profile.recorder(&super::super::super::sites_for(&plan));
        let (_, first, _) = super::super::super::mixed_run(
            chooser,
            &profile,
            plan,
            goal,
            super::super::super::LIMITS,
            &mut (),
        );
        assert_eq!(
            first,
            Some(Failure::Unsuccessful(
                "the concurrent GET was live at the check"
            ))
        );
    }

    #[test]
    fn s3_d_19_histories_end_as_declared_with_the_concurrent_get_live_at_the_check() {
        let actors = held_by("s3-d-19")
            .expect("a listed profile")
            .into_iter()
            .find(|(key, _)| *key == "actors")
            .expect("the actor bound")
            .1;
        for root in S19_ROOTS {
            for name in ["s3-d-19", "s3-d-19-mutated", "s3-d-19-retained-live"] {
                let declared = COHORTS.iter().find(|c| c.name == name).expect(name);
                let mut manifest = manifest(name)
                    .with("turns", 20_000)
                    .with("same_time", 400)
                    .with("no_progress", 5_000)
                    .with("actors", actors);
                manifest.root = root;
                let closed = traced(admit(&manifest).expect("admitted"), Vec::new());
                let events = super::super::super::take_cohort_events();
                let concurrent = super::S19_CONCURRENT_WITNESSED.take();
                let loaded =
                    load(&closed.sink, manifest.capacity().records()).expect("a loadable bundle");
                assert_eq!(
                    declared.ends_as_declared(&loaded),
                    Ok(()),
                    "{name} at {root}"
                );
                assert!(
                    events
                        .iter()
                        .any(|event| event.role == Role::Injection && event.name == super::S19[0]),
                    "{name} at {root}: setup met its premises"
                );
                assert!(concurrent, "{name} at {root}: {}", super::S19_CONCURRENT);
            }
        }
    }

    /// Each passing cohort is recorded once: it passes, its one run records
    /// one injection, one effect and one check under its own episode, and
    /// its bundle replays equal.
    #[test]
    fn every_cohort_conjoins_its_setup_effect_and_check_and_replays_equal() {
        let mut report = Vec::new();
        for cohort in COHORTS.iter().filter(|c| c.expect == Expect::Pass) {
            let (outcome, violation, bytes) = ran(cohort.name);
            assert_eq!(outcome, Outcome::Pass, "{}: {violation:?}", cohort.name);
            let events = super::super::super::take_cohort_events();
            let count = |role| {
                events
                    .iter()
                    .filter(|event| event.role == role && event.identity.episode == cohort.name)
                    .count()
            };
            let counts = [Role::Injection, Role::Effect, Role::Check].map(count);
            assert_eq!(
                counts.iter().sum::<usize>(),
                events.len(),
                "{}",
                cohort.name
            );
            report.push((cohort.name, counts));
            assert_eq!(
                replay(&bytes).expect("a replay").0,
                Replayed::Reproduced,
                "{}",
                cohort.name
            );
            super::super::super::take_cohort_events();
        }
        for (episode, [injections, effects, checks]) in &report {
            println!("{episode}: {injections} injection, {effects} effect, {checks} check");
            assert_eq!([*injections, *effects, *checks], [1, 1, 1], "{episode}");
        }
        let episodes: std::collections::BTreeSet<_> = report.iter().map(|(name, _)| name).collect();
        assert_eq!(episodes.len(), report.len());
    }

    #[test]
    fn a_mixed_setup_and_effect_fails_the_gate_and_a_missing_witness_is_unsuccessful() {
        use crate::oracle::Obligation::{Bytes, Contain, Custody, History};
        let killed = [
            (
                "c1-mixed",
                History,
                "a cohort's setup, effect and check named different identities",
            ),
            (
                "c1-reincarnated",
                History,
                "a cohort's setup, effect and check named different identities",
            ),
            (
                "c1-other-token",
                History,
                "a cohort's setup, effect and check named different identities",
            ),
            (
                "c1-out-of-order",
                History,
                "a cohort's setup, effect and check ran out of order",
            ),
            (
                "s3-d-19-mutated",
                Contain,
                "a PUT frame naming a GET changed more than its counter",
            ),
            (
                "c1-effect-after-release",
                History,
                "a cohort's setup, effect and check named different identities",
            ),
            (
                "s3-d-19-displaced-dropped",
                Custody,
                "a displacement dropped the old session's live charges",
            ),
            (
                "c1-old-cancelled",
                Bytes,
                "the old right ended without its version",
            ),
            (
                "c4-close-dropping",
                Custody,
                "a close released DATA the device still held",
            ),
        ];
        for (name, obligation, rule) in killed {
            let declared = COHORTS.iter().find(|c| c.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(obligation, rule),
                "{name}"
            );
            let (outcome, violation, _) = ran(name);
            assert_eq!(
                (outcome, violation),
                (
                    Outcome::Violation,
                    Some(failure_code(&Failure::Violation(obligation, rule)))
                ),
                "{name}"
            );
        }
        let unsuccessful = ["c1-unrecorded", "c1-duplicate", "s3-d-19-retained-live"];
        for name in unsuccessful {
            let (outcome, violation, _) = ran(name);
            assert_eq!(
                (outcome, violation),
                (Outcome::Unsuccessful, None),
                "{name}"
            );
        }
        let controls = COHORTS.iter().filter(|c| c.expect != Expect::Pass).count();
        assert_eq!(controls, killed.len() + unsuccessful.len());
    }

    #[test]
    fn a_forged_frame_passes_only_by_preserving_the_named_row_and_counting_once() {
        use super::{Counters, counter_only};
        use crate::net::requests::RequestId;
        let before = Counters {
            wrong_operation: 3,
            watermark: Some(2),
            active: Some(RequestId::from_wire(1)),
            cached: None,
            refused: None,
        };
        let counted = Counters {
            wrong_operation: 4,
            ..before
        };
        assert!(counter_only(before, counted));
        assert!(
            !counter_only(before, before),
            "a forged frame that moved no counter passed"
        );
        assert!(
            !counter_only(
                before,
                Counters {
                    wrong_operation: 5,
                    ..before
                }
            ),
            "a forged frame counted twice passed"
        );
        for changed in [
            Counters {
                watermark: Some(3),
                ..counted
            },
            Counters {
                active: None,
                ..counted
            },
            Counters {
                active: Some(RequestId::from_wire(2)),
                ..counted
            },
        ] {
            assert!(
                !counter_only(before, changed),
                "a forged frame that moved the named row's watermark or handle passed: {changed:?}"
            );
        }
        assert!(
            !counter_only(
                before,
                Counters {
                    refused: Some(2),
                    ..counted
                }
            ),
            "a forged frame that moved the named row's refused generation passed"
        );
    }

    #[test]
    fn the_named_rows_cached_epoch_expiry_and_outcome_are_preserved() {
        use super::{Counters, counter_only};
        use crate::net::datagram::PeerId;
        use crate::net::frame::Status;
        use crate::net::requests::RequestTable;
        use crate::net::serve::GetOutcome;
        use crate::net::serve_tests::{CONFIG, Core, get, session};
        use crate::storage::EngineBudget;

        let outcome = |status| {
            let mut core = Core::<Box<[u8]>>::new(
                CONFIG,
                RequestTable::new(4, 2, 2),
                2,
                128,
                0,
                4,
                &mut EngineBudget::new(1 << 20),
            )
            .expect("a core");
            let GetOutcome::Read { id, .. } = core.get(session(2), &get(0, 1, 2), 0) else {
                panic!("the GET is admitted");
            };
            core.read_refused(id, status, 0);
            core.requests
                .slot(PeerId(0), 0)
                .expect("a slot")
                .cached
                .expect("a retained outcome")
                .outcome
        };
        let retained = outcome(Status::Missing);
        let before = Counters {
            wrong_operation: 3,
            watermark: Some(1),
            active: None,
            cached: Some((4, 5_000, retained)),
            refused: None,
        };
        let counted = Counters {
            wrong_operation: 4,
            ..before
        };
        assert!(counter_only(before, counted));
        for cached in [
            None,
            Some((5, 5_000, retained)),
            Some((4, 5_001, retained)),
            Some((4, 5_000, outcome(Status::Cancelled))),
        ] {
            assert!(
                !counter_only(before, Counters { cached, ..counted }),
                "a forged frame that moved the named row's retained epoch, expiry or outcome passed: {cached:?}"
            );
        }
    }

    /// Setup requires `active + draining` to equal the issued requests plus
    /// the live refresh GETs, `draining` to stay within the live refresh
    /// count, and `retired` to equal zero.
    #[test]
    fn setup_requires_a_live_named_row_and_a_census_of_issued_and_refresh_requests() {
        use super::{Counters, s19_precondition};
        use crate::net::requests::{RequestCensus, RequestId};
        let before = Counters {
            wrong_operation: 3,
            watermark: Some(2),
            active: Some(RequestId::from_wire(1)),
            cached: None,
            refused: None,
        };
        let census = RequestCensus {
            active: 1,
            draining: 0,
            retired: 0,
        };
        assert_eq!(s19_precondition(before, census, 1, 0), Ok(()));
        assert!(
            s19_precondition(
                Counters {
                    active: None,
                    ..before
                },
                census,
                1,
                0
            )
            .is_err()
        );
        for changed in [
            RequestCensus {
                active: 2,
                ..census
            },
            RequestCensus {
                draining: 1,
                ..census
            },
            RequestCensus {
                retired: 1,
                ..census
            },
        ] {
            assert!(
                s19_precondition(before, changed, 1, 0).is_err(),
                "{changed:?}"
            );
        }
        assert!(s19_precondition(before, census, 2, 0).is_err());
        for (census, refreshed) in [
            (
                RequestCensus {
                    active: 1,
                    draining: 2,
                    retired: 0,
                },
                2,
            ),
            (
                RequestCensus {
                    active: 2,
                    draining: 1,
                    retired: 0,
                },
                2,
            ),
            (
                RequestCensus {
                    active: 2,
                    draining: 0,
                    retired: 0,
                },
                1,
            ),
        ] {
            assert_eq!(
                s19_precondition(before, census, 1, refreshed),
                Ok(()),
                "{census:?} with {refreshed} refreshed"
            );
        }
        for (census, refreshed) in [
            (
                RequestCensus {
                    active: 1,
                    draining: 2,
                    retired: 0,
                },
                1,
            ),
            (
                RequestCensus {
                    active: 0,
                    draining: 2,
                    retired: 0,
                },
                1,
            ),
            (
                RequestCensus {
                    active: 1,
                    draining: 1,
                    retired: 1,
                },
                1,
            ),
            (
                RequestCensus {
                    active: 1,
                    draining: 0,
                    retired: 0,
                },
                1,
            ),
        ] {
            assert!(
                s19_precondition(before, census, 1, refreshed).is_err(),
                "a census other than the issued requests and live refresh GETs met setup: {census:?} with {refreshed} refreshed"
            );
        }
    }

    #[test]
    fn a_named_get_reads_exactly_only_when_it_completes_with_its_version() {
        use super::super::super::super::fetch::Outcome::{Complete, Failed, Incomplete};
        use super::super::super::super::frame::Status::Cancelled;
        use super::read_exact;
        let version = super::version_a();
        assert!(read_exact(Some(Complete), &version, &version));
        assert!(!read_exact(Some(Complete), &version[1..], &version));
        assert!(
            !read_exact(Some(Failed(Cancelled)), &[], &version),
            "a failed GET read as exact"
        );
        assert!(!read_exact(
            Some(Incomplete(Cancelled)),
            &version[..10],
            &version
        ));
        assert!(!read_exact(None, &[], &version));
    }

    #[test]
    fn a_damaged_read_ends_only_with_an_integrity_failure_and_a_prefix() {
        use super::super::super::super::fetch::Outcome::{Complete, Failed};
        use super::super::super::super::frame::Status::{Cancelled, IntegrityError, TimedOut};
        use super::damaged_prefix;
        let version = super::version_a();
        assert!(damaged_prefix(Some(Failed(IntegrityError)), &[], &version));
        assert!(damaged_prefix(
            Some(Failed(IntegrityError)),
            &version[..10],
            &version
        ));
        assert!(!damaged_prefix(
            Some(Failed(IntegrityError)),
            &version[1..],
            &version
        ));
        assert!(!damaged_prefix(Some(Complete), &version, &version));
        assert!(
            !damaged_prefix(Some(Failed(Cancelled)), &[], &version),
            "a cancelled read passed as damaged"
        );
        assert!(
            !damaged_prefix(Some(Failed(TimedOut)), &version[..10], &version),
            "a timed-out read passed as damaged"
        );
        assert!(!damaged_prefix(None, &[], &version));
    }

    #[test]
    fn the_gate_rejects_each_identity_field_alone_and_any_other_order() {
        use super::super::{Event, Identity, Role};
        use super::{Rejection, conjunction};
        use crate::oracle::Label;
        use crate::storage::CommandToken;
        const NAMES: [&str; 3] = ["setup", "effect", "check"];
        let held = Some(CommandToken::from_raw(5));
        let base = Identity {
            episode: "c1",
            actor: 1,
            attempt: 7,
            label: Label(1),
            token: held,
            incarnation: Some(3),
        };
        let check = Identity {
            token: None,
            ..base
        };
        let events = |effect: Identity, check: Identity| {
            [
                (Role::Injection, base),
                (Role::Effect, effect),
                (Role::Check, check),
            ]
            .into_iter()
            .zip(NAMES)
            .enumerate()
            .map(|(at, ((role, identity), name))| Event {
                role,
                name,
                identity,
                at,
            })
            .collect::<Vec<_>>()
        };
        assert_eq!(conjunction(&events(base, check), NAMES), Ok(()));
        let effects = [
            (
                "an effect from another episode conjoined",
                Identity {
                    episode: "c2",
                    ..base
                },
            ),
            (
                "an effect from another actor conjoined",
                Identity { actor: 0, ..base },
            ),
            (
                "an effect under another attempt conjoined",
                Identity { attempt: 8, ..base },
            ),
            (
                "an effect naming another key label conjoined",
                Identity {
                    label: Label(21),
                    ..base
                },
            ),
            (
                "an effect holding another token conjoined",
                Identity {
                    token: Some(CommandToken::from_raw(6)),
                    ..base
                },
            ),
            (
                "an effect without the held token conjoined",
                Identity {
                    token: None,
                    ..base
                },
            ),
            (
                "an effect from another incarnation conjoined",
                Identity {
                    incarnation: Some(4),
                    ..base
                },
            ),
        ];
        for (conjoined, changed) in effects {
            assert_eq!(
                conjunction(&events(changed, check), NAMES),
                Err(Rejection::Mixed),
                "{conjoined}"
            );
            if changed.token.is_some() {
                assert_eq!(
                    conjunction(&events(base, changed), NAMES),
                    Err(Rejection::Mixed),
                    "check: {conjoined}"
                );
            }
            if changed.token == held {
                let tokenless_check = Identity {
                    token: None,
                    ..changed
                };
                assert_eq!(
                    conjunction(&events(base, tokenless_check), NAMES),
                    Err(Rejection::Mixed),
                    "tokenless check: {conjoined}"
                );
            }
        }
        let mut tokenless = events(base, check);
        tokenless[0].identity.token = None;
        assert_eq!(
            conjunction(&tokenless, NAMES),
            Err(Rejection::Mixed),
            "an effect holding a token its setup lacks conjoined"
        );
        tokenless[1].identity.token = None;
        assert_eq!(conjunction(&tokenless, NAMES), Ok(()));
        let mut reordered = events(base, check);
        reordered[0].at = 3;
        assert_eq!(conjunction(&reordered, NAMES), Err(Rejection::Disordered));
        let mut late_effect = events(base, check);
        late_effect[1].at = 3;
        assert_eq!(conjunction(&late_effect, NAMES), Err(Rejection::Disordered));
        let mut doubled = events(base, check);
        doubled.push(doubled[1]);
        assert_eq!(
            conjunction(&doubled, NAMES),
            Err(Rejection::Missing("effect"))
        );
        let unrecorded = &events(base, check)[1..];
        assert_eq!(
            conjunction(unrecorded, NAMES),
            Err(Rejection::Missing("setup"))
        );
    }

    #[test]
    fn every_cohort_declares_the_obligations_its_checks_witness_and_its_controls_kill() {
        use std::collections::BTreeSet;
        for cohort in &COHORTS {
            let activated: BTreeSet<_> = super::super::activated(cohort.witnesses)
                .into_iter()
                .collect();
            let declared: BTreeSet<_> = cohort.obligations.iter().copied().collect();
            assert_eq!(declared, activated, "{}", cohort.name);
            if let Expect::Violation(obligation, _) = cohort.expect {
                assert!(
                    cohort.obligations.contains(&obligation),
                    "{}: kills {obligation:?}, which it does not declare",
                    cohort.name
                );
            }
        }
    }

    #[test]
    fn unsupported_cohorts_earn_no_credit() {
        for (name, reason) in UNSUPPORTED {
            assert!(!reason.is_empty());
            let lower = name.to_lowercase();
            assert!(
                COHORTS
                    .iter()
                    .all(|cohort| !cohort.name.starts_with(&lower)),
                "{name}"
            );
        }
    }
}
