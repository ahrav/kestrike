//! A client uploads an object over a link without faults to an owner whose fill writes the
//! object's record with at least two device commands, and the upload ends `Published`. The attempt is recorded
//! as oracle rows with `net::adapters::Attempt`. Each test then judges the oracle's rule "a publication whose write
//! commands overlap on the device" twice:
//!
//! - through the oracle: `oracle::check` passes the recorded rows with `History` activated, and the rows hold
//!   one write completion that names at least two commands, each with a delivered success terminal;
//! - at the device boundary: the commands the simulated device accepted for the fill's serial
//!   (`net::adapters::written`, the device capture through the volume's token bindings) tile the record's
//!   extent. Sorted by start they begin at the extent's first byte, each begins where the one before it ends,
//!   and they end at the extent's last byte, so no two overlap and none leaves a hole. The extent is the one
//!   the storage's slot facts give the record (`Storage::slot_facts_into`), which no write command sets.
//!
//! The second test is the same history for an object of another length, one whose record takes more commands.
//!
//! Each test computes what it judges into plain values while the scene is alive and asserts after the scene
//! has returned, so a failed check ends in the test's own result line.

use super::adapters::{Attempt, FRAGMENT, tenures, written};
use super::owner_tests::PRINCIPALS;
use super::put_tests::{Scene, scene};
use super::upload::UploadOutcome;
use crate::oracle::{ActionKind, CommandEvidence, Label, Obligation, Recorder, check};
use crate::storage::IO_UNIT;

/// The key the tests upload under.
const NAME: u8 = 6;

/// What one upload left behind, read while its scene was alive.
struct Seen {
    /// How the client's upload ended, or `None` when it had not ended within the turns driven.
    outcome: Option<UploadOutcome>,
    /// The oracle passed the recorded rows with `History` activated.
    history: bool,
    /// The oracle's verdict, for a failure's message.
    verdict: String,
    /// The commands of each write completion row the attempt recorded.
    completions: Vec<Vec<CommandEvidence>>,
    /// The write commands the device accepted for the fill's serial, sorted by device start.
    device: Vec<CommandEvidence>,
    /// The device byte range of the slot extent that begins where the first command begins.
    extent: Option<std::ops::Range<u64>>,
}

/// The device byte range of the slot extent that begins at device byte `start`.
fn extent_at(scene: &Scene<'_, '_>, start: u64) -> Option<std::ops::Range<u64>> {
    let mut facts = Vec::new();
    scene.media().storage().slot_facts_into(&mut facts).ok()?;
    facts
        .iter()
        .filter_map(|fact| fact.media())
        .map(|range| range.start as u64..range.end as u64)
        .find(|range| range.start == start && !range.is_empty())
}

/// Uploads `len` bytes under `NAME` until the client decides the attempt, and returns what the oracle and the
/// device boundary show. The scene is gone when this returns.
fn upload(len: u64) -> Seen {
    let mut seen = None;
    scene(&PRINCIPALS, |mut scene| {
        let mut rec = Recorder::new(1);
        let mut slots = tenures(&scene);
        let mut attempt = Attempt::begin(&mut scene, &mut rec, (NAME, Label(1)), len, &mut slots);
        attempt.run(&mut scene, &mut rec, 600);
        let outcome = attempt.outcome;
        let mut device = attempt
            .serial
            .map(|serial| written(&scene, serial))
            .unwrap_or_default();
        device.sort_by_key(|command| command.start);
        let extent = device
            .first()
            .and_then(|first| extent_at(&scene, first.start));
        let completions = rec
            .rows()
            .iter()
            .filter(|row| row.kind == ActionKind::WriteCompleted)
            .map(|row| row.commands.clone().unwrap_or_default())
            .collect();
        let verdict = check(&rec.finish());
        seen = Some(Seen {
            outcome,
            history: verdict.satisfies(&[Obligation::History]),
            verdict: format!("{verdict:?}"),
            completions,
            device,
            extent,
        });
    });
    seen.expect("the scene ran its body")
}

/// Judges one upload of `len` bytes whose record takes at least `least` write commands.
fn judge(len: u64, least: usize) {
    let seen = upload(len);
    assert_eq!(
        seen.outcome,
        Some(UploadOutcome::Published),
        "premise: the upload of {len} bytes ends Published"
    );

    // At the device boundary: the commands the device accepted for the fill tile the record's extent.
    let device = &seen.device;
    assert!(
        device.len() >= least,
        "premise: the device accepted at least {least} write commands for the fill: {device:?}"
    );
    let overlapping: Vec<_> = device
        .windows(2)
        .filter(|pair| pair[1].start < pair[0].start + u64::from(pair[0].len))
        .collect();
    assert!(
        overlapping.is_empty(),
        "write commands of the publication overlap on the device: {overlapping:?}"
    );
    let extent = seen
        .extent
        .expect("premise: a slot extent begins where the fill's first write command begins");
    assert!(
        extent.end - extent.start >= len
            && (extent.end - extent.start).is_multiple_of(IO_UNIT as u64),
        "premise: the record's extent {extent:?} holds the object's {len} bytes in whole I/O units"
    );
    let mut end = extent.start;
    for command in device {
        assert_eq!(
            command.start, end,
            "a write command begins where the one before it ends: {device:?} over {extent:?}"
        );
        end += u64::from(command.len);
    }
    assert_eq!(
        end, extent.end,
        "the write commands end where the record's extent ends: {device:?} over {extent:?}"
    );

    // Through the oracle: the recorded history passes, and its publication rests on one write
    // completion that names every command of the fill.
    assert!(
        seen.history,
        "the oracle does not pass the published upload's history: {}",
        seen.verdict
    );
    assert_eq!(
        seen.completions.len(),
        1,
        "a published attempt records one write completion: {:?}",
        seen.completions
    );
    let recorded = &seen.completions[0];
    assert!(
        recorded.len() >= least && recorded.iter().all(CommandEvidence::succeeded),
        "the write completion names at least {least} commands, each delivered with success: {recorded:?}"
    );
    let mut by_start = recorded.clone();
    by_start.sort_by_key(|command| command.start);
    assert_eq!(
        &by_start, device,
        "the write completion names the commands the device accepted for the fill"
    );
}

/// An upload of three fragments, the last one short: the fill writes its record with more than one command.
#[test]
fn the_write_commands_of_a_published_upload_tile_its_record() {
    judge(3 * FRAGMENT as u64 - 100, 2);
}

/// The same for a longer object whose length is no multiple of the fragment or of the I/O unit.
#[test]
fn the_write_commands_of_a_longer_published_upload_tile_its_record() {
    judge(5 * FRAGMENT as u64 + 4321, 3);
}
