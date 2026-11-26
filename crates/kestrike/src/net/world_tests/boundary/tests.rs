//! Each boundary scenario crosses its boundary from below, a run that stays
//! below fails the scenario's witness, and the long run replays and its
//! planted failure reduces to a landed regression.

use crate::oracle::Obligation;
use crate::sim::action::ActionKind;
use crate::sim::manifest::Manifest;
use crate::sim::trace::{Event, Loaded, Outcome as Terminated, PAYLOAD, Terminal, load};
use crate::sim::turn::End;

use super::super::super::audit::Verdict;
use super::super::super::fetch::Outcome;
use super::super::super::frame::Status;
use super::super::super::observe::Failure;
use super::super::super::owner_tests::{OWNER, client_config};
use super::super::super::upload::UploadOutcome;
use super::super::bundle::{
    ACT, AUDIT, PUT, PutRecord, RULE, STOP, UPLOAD, UploadState, WITNESS, admit, failure_code,
    named, traced,
};
use super::super::nic_return_link;
use super::super::replay::{Edit, Replayed, Stop, premise, reduce, replay};
use super::super::{Plant, Ran, mixed, upload_code};
use super::{LARGE_LEN, collision_plan, mixed_size_plan};

/// The root every sample manifest names, so a direct run and a bundle of
/// one scenario make the same decisions.
const ROOT: u64 = 3;

/// Source slots the scene gives the uploading client.
const SOURCE_SLOTS: usize = 4;

/// The reduced scenario of the planted long run: the upload's invoke,
/// preparation, supply and outcome collection with one upload, every flag
/// cleared and every other budget zero.
const REDUCED: &str =
    "8023000000000000000000000100000000000000000000000000000000000000000000000000";

/// The manifest the reducer leaves the planted long run with: the reduced
/// scenario, the turns its last kept run took, and both link capacities
/// halved down to the last values that still keep the failure.
fn reduced_manifest() -> Manifest {
    manifest("long-planted")
        .with_scenario(REDUCED.into())
        .with("turns", 1031)
        .with("link_copy_bytes", 256)
        .with("tx_slots", 1)
}

/// Checks the bundle `loaded` of scenario `name` completed with a pass.
fn assert_passed(loaded: &Loaded, name: &str) {
    assert!(
        matches!(
            loaded.terminal,
            Terminal::Complete {
                outcome: Terminated::Pass,
                ..
            }
        ),
        "{name}: {:?}",
        loaded.terminal
    );
}

/// A manifest of `profile` pinning a placeholder executable.
fn manifest(profile: &str) -> Manifest {
    let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux");
    Manifest::parse(&text).unwrap()
}

/// The bundle a run of `manifest` records, loaded.
fn recorded(manifest: &Manifest) -> (Vec<u8>, Loaded) {
    let bytes = traced(admit(manifest).unwrap(), Vec::new()).sink;
    let loaded = load(&bytes, u64::MAX).unwrap();
    (bytes, loaded)
}

/// Runs scenario `name` directly and checks it reached its goal with a
/// passing audit.
fn run(name: &str) -> Ran {
    let (profile, plan, goal) = named(name, ROOT).unwrap();
    let ran = mixed(&profile, plan, goal);
    assert_eq!(
        (ran.report.end, ran.audit),
        (End::Done, Verdict::Pass),
        "{name}"
    );
    ran
}

/// Runs scenario `name` under `plan` in place of its own, to its own goal.
fn run_as(name: &str, plan: super::super::Plan) -> Ran {
    let (profile, _, goal) = named(name, ROOT).unwrap();
    mixed(&profile, plan, goal)
}

/// The upload published with a grant from the owner whose receipt covered
/// every fragment of `fragments`.
fn accepted(ran: &Ran, fragments: u32) -> bool {
    let receipted = ran
        .seen
        .iter()
        .any(|seen| seen.receipt == Some((fragments, fragments)));
    receipted && matches!(ran.put, Some((Some(UploadOutcome::Published), _)))
}

/// The turn the action `kind` first ran with an outcome `outcome` accepts.
fn turn(ran: &Ran, kind: ActionKind, outcome: impl Fn(u64) -> bool) -> usize {
    ran.first(kind, outcome)
        .unwrap_or_else(|| panic!("{kind:?} never ran with the outcome"))
}

#[test]
fn the_uploaders_get_is_admitted_inside_its_reserve_and_a_full_share_refuses_the_next() {
    for root in 0..24 {
        let (profile, plan, goal) = named("boundary-tiny", root).unwrap();
        let ran = mixed(&profile, plan, goal);
        assert_eq!(
            (ran.report.end, ran.audit),
            (End::Done, Verdict::Pass),
            "root {root}"
        );
        let begun = turn(&ran, ActionKind::PutInvoke, |outcome| outcome > 0);
        assert!(ran.seen[..begun].iter().all(|seen| seen.live == 0));
        let mut own: Vec<_> = ran.decided.iter().filter(|get| get.client == 0).collect();
        own.sort_by_key(|get| get.issued);
        let outcomes: Vec<_> = own.iter().map(|get| (get.outcome, get.exact)).collect();
        assert_eq!(
            outcomes,
            [
                (Outcome::Complete, true),
                (Outcome::Pressure(Status::RequestPressure), false)
            ]
        );
        for get in &own {
            assert!(begun < get.issued, "the GET runs beside the upload");
            assert!(
                ran.seen[get.issued..=get.decided]
                    .iter()
                    .all(|seen| seen.uploading)
            );
        }
        assert_eq!(
            ran.seen[own[0].issued - 1].live,
            1,
            "the upload holds one record"
        );
        assert!(
            ran.seen[own[0].issued..own[0].decided]
                .iter()
                .any(|seen| seen.live == 2),
            "the admitted GET takes the share's reserved record"
        );
        assert_eq!(
            ran.seen[own[1].issued].live, 2,
            "the refused GET meets a full share"
        );
        assert!(own[1].issued < own[0].decided);
        assert_eq!(ran.own_get, Some(Some(Outcome::Complete)));
        assert!(accepted(&ran, super::super::bundle::FRAGMENTS));
        assert_eq!(ran.get, Some((Some(Outcome::Complete), true)));
    }
}

/// The tiny-share run withholds every transmit reference until its NIC
/// return event: the uploading client's link held source fragments while
/// the client's slots held them, and a return event for a link lowered the
/// count that link withholds.
#[test]
fn withheld_transmits_return_on_their_nic_events() {
    let ran = run("boundary-tiny");
    assert!(
        ran.seen
            .iter()
            .any(|seen| seen.withheld[0] > 0 && seen.sources > 0),
        "the link withheld fragments the client's source slots held"
    );
    let returned = (1..ran.seen.len()).filter(|&at| {
        nic_return_link(&ran.report.turns[at].event)
            .is_some_and(|link| ran.seen[at].withheld[link] < ran.seen[at - 1].withheld[link])
    });
    assert!(
        returned.count() > 0,
        "a NIC return event released a reference"
    );
}

/// Whether the GET client's read of a key nothing was published under met
/// a fingerprint collision: the owner's false-positive count crossed from
/// zero to one between two turns and stayed there, and the read ended
/// `Missing` with no byte.
fn collided(ran: &Ran) -> bool {
    let crossed = ran
        .seen
        .windows(2)
        .any(|pair| pair[0].false_positives == 0 && pair[1].false_positives == 1);
    let last = ran.seen.last().map(|seen| seen.false_positives);
    crossed && last == Some(1) && ran.get == Some((Some(Outcome::Missing), true))
}

/// The stranger key hashes to the resident object's word, so the GET
/// client's read, issued after the upload published, finds the resident
/// record, sees another key in its header and ends `Missing` with no byte,
/// counted once as a false positive. The same run whose index hashes every
/// key apart ends `Missing` too, with no false positive, so it fails the
/// witness.
#[test]
fn a_shared_fingerprint_is_counted_once_and_answers_missing() {
    let ran = run("boundary-collision");
    assert!(collided(&ran), "{:?}", ran.get);
    assert!(accepted(&ran, super::super::bundle::FRAGMENTS));
    let published = upload_code(UploadOutcome::Published);
    let collected = turn(&ran, ActionKind::PutOutcome, |outcome| outcome == published);
    let issued = turn(&ran, ActionKind::Get, |outcome| outcome > 0);
    assert!(collected < issued, "the read follows the publication");
    let apart = run_as("boundary-collision", collision_plan(false));
    assert_eq!(apart.report.end, End::Done);
    assert_eq!(apart.get, Some((Some(Outcome::Missing), true)));
    assert!(
        !collided(&apart),
        "a run with no collision fails the witness"
    );
}

fn fills_reuse_the_hole(extents: &super::super::Extents) -> Result<(), String> {
    let (Some(local), Some(upload)) = (&extents.local, &extents.upload) else {
        return Err("the local object or the upload never placed".into());
    };
    if local.end > upload.start {
        return Err("the local object lies past the upload".into());
    }
    if extents.pressure.first() != Some(local) {
        return Err("the first fill left the freed extent".into());
    }
    if extents.pressure.len() < 2 {
        return Err("no fill followed the one in the freed extent".into());
    }
    if !extents.pressure[1..]
        .iter()
        .all(|fill| fill.start >= upload.end)
    {
        return Err("a later fill landed below the upload".into());
    }
    Ok(())
}

#[test]
fn a_lone_fill_in_the_hole_fails_the_fragmentation_witness() {
    let extents = |pressure: Vec<std::ops::Range<usize>>| super::super::Extents {
        local: Some(100..200),
        pressure,
        upload: Some(200..400),
    };
    assert_eq!(
        fills_reuse_the_hole(&extents(vec![100..200, 400..500])),
        Ok(())
    );
    assert!(
        fills_reuse_the_hole(&extents(std::iter::once(100..200).collect())).is_err(),
        "no fill past the upload"
    );
}

/// The local object publishes into the extent after the resident one and
/// the upload into the extent after it. The local object's expiry returns
/// its extent on one turn: the storage's retired bytes fall to zero and its
/// free bytes rise by exactly the local object's extent, with no pressure
/// fill reserved before that turn. The first fill pressure reserves after
/// it takes exactly the freed extent, below the upload's, and the next
/// takes fresh space past the upload.
#[test]
fn a_fill_after_an_expiry_lands_in_the_freed_extent() {
    let ran = run("boundary-fragmentation");
    let extents = &ran.extents;
    assert_eq!(fills_reuse_the_hole(extents), Ok(()), "{extents:?}");
    let local = extents.local.clone().expect("the local object published");
    let raw: Vec<_> = ran
        .seen
        .iter()
        .map(|seen| seen.raw.expect("the ledger reads"))
        .collect();
    let freed = (1..raw.len())
        .find(|&at| {
            let (before, after) = (raw[at - 1], raw[at]);
            before.retired > 0 && after.retired == 0 && after.free == before.free + local.len()
        })
        .expect("the expiry returned the local object's extent");
    let reserved = turn(&ran, ActionKind::Pressure, |outcome| outcome > 0);
    assert!(freed < reserved, "pressure reserves into the opened hole");
    assert_eq!(ran.get, Some((Some(Outcome::Complete), true)));
    assert!(accepted(&ran, super::super::bundle::FRAGMENTS));
}

/// Without the fragmenting gate pressure reserves while the local object
/// is still resident, so its first fill lands past the upload's extent and
/// never in the local object's.
#[test]
fn a_fill_before_the_expiry_lands_past_the_upload() {
    let (_, plan, _) = named("boundary-fragmentation", ROOT).unwrap();
    let ran = run_as(
        "boundary-fragmentation",
        super::super::Plan {
            fragmenting: false,
            ..plan
        },
    );
    assert_eq!(ran.audit, Verdict::Pass);
    let extents = &ran.extents;
    let (local, upload) = (
        extents.local.clone().expect("the local object published"),
        extents.upload.clone().expect("the upload is bound"),
    );
    let first = extents.pressure.first().expect("pressure reserved a fill");
    assert!(first.start >= upload.end, "{extents:?}");
    assert!(!extents.pressure.contains(&local), "{extents:?}");
}

/// A six-fragment upload outgrows the uploading client's four source slots
/// and the owner's PUT window of four. The slots fill one at a time to
/// four, a supply is refused while all four hold fragments, and a later
/// supply is taken. A receipt with base zero grants exactly the window,
/// short of the object, every grant stays within the window past the
/// receipt base, and the last receipt covers all six. The uploading
/// client's GET of the 1000-byte resident object completes and the other
/// client's GET of the upload reads exactly.
#[test]
fn a_six_fragment_upload_crosses_its_source_slots_and_window() {
    let ran = run("boundary-mixed-size");
    let fragments = LARGE_LEN.div_ceil(super::super::FRAGMENT_LEN);
    assert_eq!(fragments, 6);
    let window = OWNER.put.window;
    assert!(window < fragments && SOURCE_SLOTS < fragments as usize);
    let rose = ran
        .seen
        .windows(2)
        .any(|pair| pair[0].sources == SOURCE_SLOTS - 1 && pair[1].sources == SOURCE_SLOTS);
    assert!(rose, "the slots filled from below");
    assert!(ran.seen.iter().all(|seen| seen.sources <= SOURCE_SLOTS));
    let refused = ran
        .acts
        .iter()
        .find(|act| {
            act.kind == ActionKind::Supply
                && act.outcome == super::super::REFUSED
                && ran.seen[act.turn].sources == SOURCE_SLOTS
        })
        .expect("a supply was refused while every slot held a fragment");
    assert!(
        ran.acts.iter().any(|act| act.kind == ActionKind::Supply
            && act.outcome > 0
            && act.turn > refused.turn)
    );
    let receipts: Vec<(u32, u32)> = ran.seen.iter().filter_map(|seen| seen.receipt).collect();
    assert!(receipts.contains(&(0, window)), "{receipts:?}");
    assert!(
        receipts
            .iter()
            .all(|&(base, grant)| grant <= (base + window).min(fragments))
    );
    assert!(accepted(&ran, fragments), "{receipts:?}");
    assert_eq!(ran.own_get, Some(Some(Outcome::Complete)));
    assert_eq!(ran.get, Some((Some(Outcome::Complete), true)));
}

/// The mixed-size upload's PUT core needs two write commands on its
/// busiest owner turn. With two per turn, the owner's write commands rise
/// by two on that turn and no consume pass waits for one. With one per
/// turn, they rise by at most one per turn, a consume pass waits on the
/// turn the first command is spent, and the upload still publishes with
/// every fragment receipted, the uploading client's GET completes and the
/// other client's GET reads the upload exactly.
#[test]
fn a_one_command_turn_quota_holds_received_data_until_the_next_turn() {
    let rises = |ran: &Ran| -> Vec<(u64, u64)> {
        ran.seen
            .windows(2)
            .map(|pair| {
                let (before, after) = (pair[0].writes, pair[1].writes);
                (after.0 - before.0, after.1 - before.1)
            })
            .collect()
    };
    let fragments = LARGE_LEN.div_ceil(super::super::FRAGMENT_LEN);
    let at = run_as("boundary-mixed-size", mixed_size_plan(Some(2)));
    assert_eq!((at.report.end, at.audit), (End::Done, Verdict::Pass));
    let at_rises = rises(&at);
    assert_eq!(at_rises.iter().map(|rise| rise.0).max(), Some(2));
    assert!(at.seen.iter().all(|seen| seen.writes.1 == 0));
    let below = run_as("boundary-mixed-size", mixed_size_plan(Some(1)));
    assert_eq!((below.report.end, below.audit), (End::Done, Verdict::Pass));
    let below_rises = rises(&below);
    assert!(
        below_rises.iter().all(|rise| rise.0 <= 1),
        "{below_rises:?}"
    );
    let first = below_rises
        .iter()
        .position(|rise| rise.0 > 0)
        .expect("a write command was submitted");
    assert_eq!(below_rises[first], (1, 1), "the quota was spent and waited");
    assert!(accepted(&below, fragments));
    assert_eq!(below.own_get, Some(Some(Outcome::Complete)));
    assert_eq!(below.get, Some((Some(Outcome::Complete), true)));
}

fn resends_reach(steps: &[(usize, bool)], limit: usize) -> Result<(), String> {
    if steps.windows(2).any(|pair| pair[1].0 > pair[0].0 + 1) {
        return Err("the dropped BEGINs rose by more than one in a turn".into());
    }
    let decided = steps
        .iter()
        .position(|&(begins, uploading)| !uploading && begins > 0)
        .ok_or("the upload was never decided")?;
    if steps[decided].0 != limit {
        return Err(format!("decided after {} BEGINs", steps[decided].0));
    }
    for want in [limit - 1, limit] {
        if !steps[..decided].iter().any(|&(begins, _)| begins == want) {
            return Err(format!("no undecided turn after {want} BEGINs"));
        }
    }
    if steps.iter().any(|&(begins, _)| begins > limit) {
        return Err("more BEGINs than the limit".into());
    }
    Ok(())
}

#[test]
fn a_decision_on_the_last_resend_fails_the_resend_witness() {
    let waited = [(0, true), (1, true), (2, true), (3, true), (3, false)];
    assert_eq!(resends_reach(&waited, 3), Ok(()));
    let at_once = [(0, true), (1, true), (2, true), (3, false)];
    assert!(
        resends_reach(&at_once, 3).is_err(),
        "the upload decided on the turn its last BEGIN dropped"
    );
}

/// Every PUT BEGIN on the uploading client's link is dropped: the dropped
/// count rises by at most one per turn, the upload stays undecided at the
/// client's resend limit and through its last resend, and it ends `Unknown`
/// on a later turn with exactly the first send and every resend dropped.
/// The GET of the resident object beside it reads exactly.
#[test]
fn begin_resends_count_to_their_limit_and_the_upload_ends_unknown() {
    let ran = run("boundary-real-counter");
    let limit = client_config(0).upload.attempts as usize + 1;
    let steps: Vec<(usize, bool)> = ran
        .seen
        .iter()
        .map(|seen| (seen.begins, seen.uploading))
        .collect();
    assert_eq!(resends_reach(&steps, limit), Ok(()));
    assert_eq!(ran.put, Some((Some(UploadOutcome::Unknown), 0)));
    assert_eq!(ran.get, Some((Some(Outcome::Complete), true)));
}

/// Bytes each event kind lays out; the rest of its payload is zero.
fn laid_out(kind: u8) -> Option<usize> {
    match kind {
        ACT | WITNESS => Some(9),
        PUT => Some(43),
        UPLOAD => Some(22),
        AUDIT => Some(8),
        RULE => Some(33),
        STOP => Some(15),
        _ => None,
    }
}

const BOUNDARIES: [&str; 5] = [
    "boundary-tiny",
    "boundary-collision",
    "boundary-fragmentation",
    "boundary-mixed-size",
    "boundary-real-counter",
];

/// Every boundary scenario's frames and records leave their reserved
/// fields zero. At every turn the newest datagram in flight in each
/// direction parses as a frame, so its reserved fields are zero, since the
/// parser refuses a nonzero one; some turn parsed at least one. Each scenario's bundle passes
/// and replays, and every event's payload past its laid-out fields is zero.
#[test]
fn boundary_frames_and_records_keep_reserved_fields_zero() {
    for name in BOUNDARIES {
        let ran = run(name);
        let errors: Vec<_> = ran
            .seen
            .iter()
            .flat_map(|seen| seen.frames.1)
            .flatten()
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        assert!(ran.seen.iter().any(|seen| seen.frames.0 > 0), "{name}");
        let (bytes, loaded) = recorded(&manifest(name));
        assert_passed(&loaded, name);
        assert_eq!(replay(&bytes).unwrap().0, Replayed::Reproduced, "{name}");
        for event in &loaded.events {
            let len = laid_out(event.kind).unwrap_or(PAYLOAD);
            assert!(
                event.payload[len..].iter().all(|&byte| byte == 0),
                "{name}: {event:?}"
            );
        }
    }
}

/// Where attempt `attempt`'s source custody stands in `events`: the
/// position of the first state of the attempt showing a device holding a
/// source slot, and the position of the state immediately after the
/// attempt's final slot-holding state, counting only states recorded before
/// the next attempt's first record. A held count that rises after the
/// attempt's published state fails the witness.
fn custody(events: &[Event], attempt: u16) -> Result<(usize, usize), String> {
    let attempt_of = |event: &Event| {
        UploadState::of(event)
            .map(|state| state.attempt)
            .or_else(|| PutRecord::of(event).map(|put| put.attempt))
    };
    let next = events
        .iter()
        .position(|event| attempt_of(event).is_some_and(|other| other > attempt))
        .unwrap_or(events.len());
    let states: Vec<(usize, UploadState)> = events[..next]
        .iter()
        .enumerate()
        .filter_map(|(at, event)| UploadState::of(event).map(|state| (at, state)))
        .filter(|(_, state)| state.attempt == attempt)
        .collect();
    let held = states
        .iter()
        .position(|(_, state)| state.held > 0)
        .ok_or("no device held a source slot")?;
    let last_held = states
        .iter()
        .rposition(|(_, state)| state.held > 0)
        .expect("the first held state is a held state");
    let returned = Some(last_held + 1)
        .filter(|&at| at < states.len())
        .ok_or("its source slots did not return before the next attempt")?;
    let published = UploadState::code(UploadOutcome::Published);
    let from = states
        .iter()
        .position(|(_, state)| state.outcome == published)
        .ok_or("no state shows the attempt published")?;
    if states[from..]
        .windows(2)
        .any(|pair| pair[1].1.held > pair[0].1.held)
    {
        return Err("a source slot was taken again after the publication".into());
    }
    Ok((states[held].0, states[returned].0))
}

fn upload_event(attempt: u16, held: u16, outcome: u8) -> Event {
    let mut payload = [0; PAYLOAD];
    payload[0..2].copy_from_slice(&attempt.to_le_bytes());
    payload[18..20].copy_from_slice(&held.to_le_bytes());
    payload[20] = outcome;
    Event {
        kind: UPLOAD,
        payload,
    }
}

#[test]
fn custody_requires_every_slot_returned_at_the_attempts_last_state() {
    let published = UploadState::code(UploadOutcome::Published);
    let events = |held: [u16; 4]| -> Vec<Event> {
        held.iter()
            .enumerate()
            .map(|(at, &held)| upload_event(1, held, if at >= 2 { published } else { 0 }))
            .chain([upload_event(2, 0, 0)])
            .collect()
    };
    assert!(
        custody(&events([1, 0, 1, 1]), 1).is_err(),
        "a slot still held when the next attempt begins"
    );
    assert_eq!(custody(&events([1, 0, 1, 0]), 1), Ok((0, 3)));
}

/// The long mixed run replays `Reproduced`, and its bundle carries the
/// witnesses: two upload attempts with distinct fill serials each publish,
/// each with an outcome collected as published and a bound key; for each
/// published attempt a device held a source slot and every slot returned
/// before the next attempt's first record, with no slot taken again after
/// the publication; and every planned GET ran.
#[test]
fn the_long_mixed_run_replays_with_its_witnesses() {
    let (bytes, loaded) = recorded(&manifest("long"));
    assert_passed(&loaded, "long");
    assert!(loaded.work.turns > u64::from(super::LONG_DRAIN));
    assert_eq!(replay(&bytes).unwrap().0, Replayed::Reproduced);
    let states: Vec<UploadState> = loaded.events.iter().filter_map(UploadState::of).collect();
    let published = UploadState::code(UploadOutcome::Published);
    // An attempt's serial clears once its sources return and it publishes, so a publishing attempt's serial is read from any of its states.
    let bound: std::collections::BTreeSet<u16> = states
        .iter()
        .filter(|state| state.outcome == published && state.bound)
        .map(|state| state.attempt)
        .collect();
    let serials: std::collections::BTreeSet<u64> = states
        .iter()
        .filter(|state| bound.contains(&state.attempt) && state.serial > 0)
        .map(|state| state.serial)
        .collect();
    assert_eq!(serials.len(), 2, "{states:?}");
    let attempts: std::collections::BTreeSet<u16> = states
        .iter()
        .filter(|state| state.outcome == published)
        .map(|state| state.attempt)
        .collect();
    assert_eq!(attempts.len(), 2);
    for &attempt in &attempts {
        let custody = custody(&loaded.events, attempt);
        assert!(custody.is_ok(), "attempt {attempt}: {custody:?}");
    }
    let collected = loaded
        .events
        .iter()
        .filter_map(PutRecord::of)
        .filter(|put| {
            put.kind == Some(ActionKind::PutOutcome)
                && u64::from(put.outcome) == upload_code(UploadOutcome::Published)
        });
    assert_eq!(collected.count(), 2);
    let gets = loaded.events.iter().filter(|event: &&Event| {
        event.kind == WITNESS && event.payload[0] == ActionKind::Get as u8
    });
    assert_eq!(gets.count(), 4);
}

/// Replays `bytes` in process and says whether it reproduced.
fn reproduced(bytes: &[u8], _: &super::super::replay::Identity) -> Result<bool, String> {
    Ok(matches!(replay(bytes), Ok((Replayed::Reproduced, _))))
}

/// The violation a changed published record raises at the next stopped
/// boundary.
fn changed_record() -> [u8; PAYLOAD] {
    failure_code(&Failure::Violation(
        Obligation::Bytes,
        "a bound slot's record fails its header or chunk checks",
    ))
}

/// The long run with a payload byte of its first published record changed
/// ends in that record's `Bytes` violation. The reducer keeps the violation
/// and the plant's premise, and lands on a scenario that declares exactly
/// the upload's invoke, preparation, supply and outcome collection with
/// one upload and no GET, both link capacities and the turn bound at most
/// the original's, a smaller bundle, and a replay that reproduces.
#[test]
fn the_planted_long_run_reduces_to_its_regression() {
    let original = manifest("long-planted");
    let (bytes, loaded) = recorded(&original);
    assert_eq!(loaded.violation, Some(changed_record()));
    let reduced = reduce(&bytes, &mut reproduced).unwrap();
    assert_eq!(reduced.stop, Stop::Exhausted, "{:?}", reduced.steps);
    let ran = load(&reduced.bundle, u64::MAX).unwrap();
    assert_eq!(ran.violation, loaded.violation);
    assert_eq!(premise(Plant::PublishedByte, &ran), Some(true));
    let (profile, plan, _) = named("long-planted", ROOT).unwrap();
    let edit = Edit::decode(&reduced.manifest.scenario).expect("an encoded edit");
    let (kept, plan) = edit.apply(&profile, plan).expect("the edit applies");
    assert_eq!(
        kept.declared,
        [
            ActionKind::PutInvoke,
            ActionKind::PutPrepare,
            ActionKind::Supply,
            ActionKind::PutOutcome,
        ],
        "{:?}",
        reduced.steps
    );
    assert_eq!((plan.puts, plan.gets), (1, [0, 0]));
    for bound in ["link_copy_bytes", "tx_slots", "turns"] {
        assert!(
            reduced.manifest.count(bound) <= original.count(bound),
            "{bound}"
        );
    }
    assert!(reduced.bundle.len() < bytes.len());
    assert_eq!(replay(&reduced.bundle).unwrap().0, Replayed::Reproduced);
}

/// The landed regression of the planted long run: its scenario keeps one
/// upload's invoke, preparation, supply and outcome collection, and its run
/// still ends in the changed record's `Bytes` violation with the plant's
/// premise, and replays.
#[test]
fn the_reduced_long_run_keeps_its_violation() {
    let (profile, plan, _) = named("long-planted", ROOT).unwrap();
    let edit = Edit::decode(REDUCED).unwrap();
    let (kept, reduced) = edit.apply(&profile, plan).unwrap();
    assert_eq!(
        kept.declared,
        [
            ActionKind::PutInvoke,
            ActionKind::PutPrepare,
            ActionKind::Supply,
            ActionKind::PutOutcome,
        ]
    );
    assert_eq!((reduced.puts, reduced.gets), (1, [0, 0]));
    assert!(!reduced.link_faults && reduced.plant == Plant::PublishedByte);
    let (bytes, loaded) = recorded(&reduced_manifest());
    assert!(matches!(
        loaded.terminal,
        Terminal::Complete {
            outcome: Terminated::Violation,
            ..
        }
    ));
    assert_eq!(loaded.violation, Some(changed_record()));
    assert_eq!(premise(Plant::PublishedByte, &loaded), Some(true));
    assert_eq!(replay(&bytes).unwrap().0, Replayed::Reproduced);
}
