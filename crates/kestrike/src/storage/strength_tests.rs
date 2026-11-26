//! Oracle strength: one storage episode per live obligation, each run
//! through the production storage, volume and simulated-disk paths.
//!
//! An episode records each judged production result, the outcome of each
//! watched lookup and of each read that reached its `Done`, with its bytes,
//! lengths and allocation, and the commands, buffers and slots production
//! took, and leaves their judgment to the history oracle. Setup the episode builds on, a registration or the
//! fixture's publication, still panics when production refuses it;
//! maintenance calls and the funded publication attempts tolerate refusal.
//! Each episode names a premise over its rows, the production transitions
//! a pass must have exercised. A healthy episode must pass, activate its
//! obligation and hold its premise.
//! Its planted defect must fail with exactly that obligation's named rule,
//! at the operation the plant names, in the episode that operation's rows
//! carry. A healthy episode the oracle rejects panics with one rejection
//! line, `<alias> rejected "<rule>" at <op> in <episode>`, naming the
//! episode from the violating operation's rows. That line is the format a
//! mutation harness matches to credit a kill to an oracle; a pass without
//! its premise, a verdict that activates nothing and every other panic
//! print no such line.

use std::collections::BTreeSet;

use super::device::sim::Event;
use super::device::{CommandToken, Operation};
use super::evict_tests::drain;
use super::oracle_custody_tests::{
    META, Watch, allocation, buffer, command, generated, held, identity, in_use, lengths,
};
use super::owner_fixture::{
    CHUNK_LEN, QuiesceMode, SimControl, arena, invalidate, last_read, publish, storage,
};
use super::publish_tests::{TRIES, budget, key};
use super::test_platform::TestPlatform;
use super::volume::{ReadEvent, ReadOp, ReadStatus, VerifiedReadInfo};
use super::volume_fixture::Device;
use super::writable_tests::reserve;
use super::{BufferArena, ExtentLease, Storage};
use crate::index::Key;
use crate::oracle::{
    ActionKind, Checkpoint, ClockSample, Custodian, Episode, EvidenceLabel, Failure, Geometry,
    KeyId, Label, NoInformation, OBLIGATIONS, Obligation, OpId, Outcome, Recorder, ReportKind,
    ResourceKind, Row, SearchBudget, Verdict, Violation, VisibilityCause, check_within,
};
use crate::sim::round::{Act, Actor, round};

const K: KeyId = KeyId(0);
const KEEP: KeyId = KeyId(1);
const NEXT: KeyId = KeyId(2);
const A: Label = Label(1);
const B: Label = Label(2);
const C: Label = Label(3);
/// Payload of the one-chunk objects: metadata and body in one window.
const SMALL: usize = 3000;
/// Payload of the damaged object: three chunk lengths plus 100 bytes,
/// spanning four chunks.
const PAYLOAD: usize = 3 * CHUNK_LEN as usize + 100;
const RECORD: Geometry = Geometry {
    chunk: CHUNK_LEN as usize,
    header: 108 + (PAYLOAD.div_ceil(CHUNK_LEN as usize) + 1) * 4,
};
/// Ticks a read may take to its `Done` before the episode stops driving it.
const TICKS: usize = 64;
/// Funded actions the reclaim episode may spend: each maintenance call and
/// each publication attempt counts one.
const FUNDED: u32 = 8;
/// Turns the healthy owner may take to serve its read beside the failed one.
const SERVE_BOUND: u32 = 16;

/// One live obligation's episode, its planted defect and the rule the
/// defect must break.
struct Strength {
    obligation: Obligation,
    episode: &'static str,
    /// Episode number the episode's rows carry; distinct across the table.
    id: u16,
    run: fn(u16) -> Vec<Row>,
    /// Whether the rows hold what a pass must have exercised: the
    /// production transitions the obligation judges. A pass without them
    /// earns no credit; a violation names its oracle whatever the premise.
    premise: fn(&[Row]) -> bool,
    /// Changes the healthy rows into the defective history and names the
    /// operation the oracle must blame.
    plant: fn(Vec<Row>) -> (Vec<Row>, OpId),
    /// The rule the planted defect must break.
    rule: &'static str,
}

static STRENGTH: [Strength; 7] = [
    Strength {
        obligation: Obligation::Bytes,
        episode: "exact-read",
        id: 101,
        run: exact_read,
        premise: complete_read,
        plant: wrong_byte,
        rule: "a complete read returned bytes other than the label's content",
    },
    Strength {
        obligation: Obligation::History,
        episode: "acknowledged-invalidation",
        id: 102,
        run: acknowledged_invalidation,
        premise: lookup_after_invalidation,
        plant: stale_hit,
        rule: "a hit of a version an acknowledged invalidation covered",
    },
    Strength {
        obligation: Obligation::Custody,
        episode: "reclaim-and-reuse",
        id: 103,
        run: reclaimed_extent_reuse,
        premise: reclaim_and_reuse,
        plant: overlapping_extent,
        rule: "writable extents overlapped",
    },
    Strength {
        obligation: Obligation::Resources,
        episode: "released-read",
        id: 104,
        run: released_read,
        premise: released_reports,
        plant: lost_credit,
        rule: "a production report disagreed with the independent count",
    },
    Strength {
        obligation: Obligation::Progress,
        episode: "funded-reclaim",
        id: 105,
        run: funded_reclaim,
        premise: funded_recovery,
        plant: over_budget,
        rule: "funded recovery exceeded its action bound",
    },
    Strength {
        obligation: Obligation::Isolation,
        episode: "failed-owner-beside-healthy",
        id: 106,
        run: failed_owner_beside_healthy,
        premise: retained_beside_healthy,
        plant: blocked_peer,
        rule: "a healthy owner starved past its fixture bound",
    },
    Strength {
        obligation: Obligation::Contain,
        episode: "damaged-later-chunk",
        id: 107,
        run: damaged_later_chunk,
        premise: second_chunk_mismatch,
        plant: failed_chunk_bytes,
        rule: "bytes from a failed chunk or a later one were exposed",
    },
];

fn alias(obligation: Obligation) -> &'static str {
    OBLIGATIONS[obligation as usize].alias
}

fn judged(rows: &[Row]) -> Verdict {
    check_within(
        &Recorder::rebuilt(rows.iter().cloned()),
        RECORD,
        &mut SearchBudget::per_key(),
    )
}

fn strength(obligation: Obligation) -> &'static Strength {
    STRENGTH
        .iter()
        .find(|s| s.obligation == obligation)
        .expect("a strength row")
}

/// The name of the episode whose rows carry operation `op`, or `"no
/// episode"` when no row of `op` carries one of the table's episodes.
fn episode_of(rows: &[Row], op: OpId) -> &'static str {
    rows.iter()
        .filter(|row| row.op == op)
        .find_map(|row| {
            STRENGTH
                .iter()
                .find(|s| row.episode == Some(Episode(u64::from(s.id))))
        })
        .map_or("no episode", |s| s.episode)
}

/// Runs `obligation`'s episode, requires a pass that activates the
/// obligation, then requires the planted defect's exact violation in the
/// episode's own rows.
fn attributed(obligation: Obligation) {
    let s = strength(obligation);
    let rows = (s.run)(s.id);
    match judged(&rows) {
        Verdict::Pass(activations) if activations.count(obligation) > 0 => {
            assert!(
                (s.premise)(&rows),
                "{} passed without its premise",
                s.episode
            );
        }
        Verdict::Violation(v) => panic!(
            "{} rejected {:?} at {:?} in {}",
            alias(v.obligation),
            v.rule,
            v.op,
            episode_of(&rows, v.op)
        ),
        other => panic!(
            "{} judged {other:?} without activating {}",
            s.episode,
            alias(obligation)
        ),
    }
    let (planted, op) = (s.plant)(rows);
    assert_eq!(
        judged(&planted),
        Verdict::Violation(Violation {
            obligation,
            op,
            rule: s.rule,
        }),
        "{}'s plant",
        s.episode
    );
    assert_eq!(episode_of(&planted, op), s.episode);
}

/// What one read did: its ending, its verified header, its handed-off
/// bytes in event order, every response buffer it held at a tick, and the
/// ticks it took.
struct Read {
    status: ReadStatus,
    info: Option<VerifiedReadInfo>,
    bytes: Vec<u8>,
    buffers: BTreeSet<(u32, u64)>,
    ticks: u32,
}

/// Ticks `op` to its `Done`, granting its next command after each chunk,
/// or returns `None` when no `Done` arrived within [`TICKS`]. Each tick
/// turns both devices' disks and volumes as one controller round, a
/// `beside` volume listed first and its events dropped.
fn collected(
    (device, arena): (&mut Device<'_, '_>, &BufferArena<TestPlatform>),
    op: ReadOp,
    before: &BTreeSet<(u32, u64)>,
    mut beside: Option<&mut Device<'_, '_>>,
) -> Option<Read> {
    let (mut out, mut bytes, mut seen) = (Vec::with_capacity(8), Vec::new(), None);
    let mut buffers = BTreeSet::new();
    for ticks in 1..=TICKS as u32 {
        let mut acts = Vec::with_capacity(4);
        let (mut beside_tick, mut beside_poll);
        if let Some(beside) = beside.as_deref_mut() {
            let (volume, control) = (&mut beside.volume, &beside.control);
            beside_tick = move || control.tick(64);
            beside_poll = || {
                let mut dropped = Vec::with_capacity(8);
                let _ = volume.poll_storage(0, &mut dropped);
            };
            acts.push(Act::new(Actor::Disk(1), &mut beside_tick));
            acts.push(Act::new(Actor::Volume(1), &mut beside_poll));
        }
        let mut tick = || {
            buffers.extend(in_use(arena).difference(before).copied());
            device.control.tick(64);
        };
        let mut poll = || {
            let _ = device.volume.poll_storage(0, &mut out);
        };
        acts.push(Act::new(Actor::Disk(0), &mut tick));
        acts.push(Act::new(Actor::Volume(0), &mut poll));
        round(&mut acts);
        drop(acts);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk {
                    op: of,
                    info,
                    chunk,
                    ..
                } if of == op => {
                    seen = Some(info);
                    let _ = device.volume.grant_read(op);
                    bytes.extend_from_slice(chunk.bytes());
                }
                ReadEvent::Done {
                    op: of,
                    info,
                    status,
                } if of == op => {
                    return Some(Read {
                        status,
                        info: info.or(seen),
                        bytes,
                        buffers,
                        ticks,
                    });
                }
                _ => {}
            }
        }
    }
    None
}

fn outcome(status: ReadStatus) -> Outcome {
    match status {
        ReadStatus::Complete => Outcome::Complete,
        ReadStatus::HeaderMismatch(_) => Outcome::Damaged(Failure::HeaderMismatch),
        ReadStatus::ChunkMismatch { index } => Outcome::Damaged(Failure::ChunkMismatch { index }),
        ReadStatus::DeviceError => Outcome::Damaged(Failure::DeviceError),
        ReadStatus::Short => Outcome::Damaged(Failure::Short),
        ReadStatus::Quiesced => Outcome::Damaged(Failure::Quiesced),
        ReadStatus::Lost => Outcome::Damaged(Failure::Lost),
        ReadStatus::Cancelled => Outcome::NoInformation(NoInformation::Cancelled),
        ReadStatus::TimedOut => Outcome::NoInformation(NoInformation::TimedOut),
    }
}

/// The terminal recorded for a read's last command: `DeviceError` or
/// `Short` when the read ended in one, otherwise success. Header and chunk
/// mismatches are decided after the command completed. The episodes'
/// storage reads one command at a time, so the read's last command is the
/// one that ended it.
fn device_result(status: ReadStatus) -> Outcome {
    match status {
        ReadStatus::DeviceError => Outcome::Damaged(Failure::DeviceError),
        ReadStatus::Short => Outcome::Damaged(Failure::Short),
        _ => Outcome::Complete,
    }
}

/// The read commands the device accepted since event `mark`.
fn reads_since(control: &SimControl, mark: usize) -> Vec<CommandToken> {
    control.events()[mark..]
        .iter()
        .filter_map(|event| match event {
            Event::Submitted(token, Operation::Read) => Some(*token),
            _ => None,
        })
        .collect()
}

/// Reads `lease`'s object for the lookup `op` and records the delivery
/// under the lengths and allocation the verified header carried, the
/// publication's when no header verified. Every read command and response
/// buffer the read held is recorded taken; once the read ended, each
/// command no longer pending in production's table is recorded at its terminal
/// and each buffer production freed is recorded returned. When the volume
/// refuses the read nothing is recorded; when no `Done` arrives within
/// [`TICKS`], only the duplicate's take is.
fn delivered<'s>(
    w: &mut Watch,
    (device, arena): (&mut Device<'s, '_>, &BufferArena<TestPlatform>),
    lease: &ExtentLease<'s, TestPlatform>,
    (op, (key, label), len): (OpId, (KeyId, Label), usize),
    beside: Option<&mut Device<'_, '_>>,
) -> Option<u32> {
    let (metadata, body) = lengths(len);
    let at = held(lease);
    let (before, mark) = (in_use(arena), device.control.events().len());
    let Ok(read) = device.volume.read(lease.duplicate(), u64::MAX) else {
        return None;
    };
    w.duplicate_taken(at);
    let done = collected((device, arena), read, &before, beside)?;
    let commands: Vec<_> = reads_since(&device.control, mark)
        .into_iter()
        .map(command)
        .collect();
    for &token in &commands {
        w.rec.take(token, Custodian::Storage, None);
    }
    for &taken in &done.buffers {
        w.rec.take(buffer(taken), Custodian::Storage, None);
    }
    let (lengths, identity) = done.info.map_or(
        ((metadata, body), (device.volume.session(), allocation(at))),
        |info| {
            (
                (info.metadata_len(), u64::from(info.body_len())),
                (info.identity().session, info.identity().allocation),
            )
        },
    );
    w.rec.delivered(
        op,
        (key, label),
        lengths,
        identity,
        outcome(done.status),
        done.bytes,
    );
    let pending: Vec<_> = device
        .volume
        .table_tokens()
        .into_iter()
        .filter_map(|(token, pending)| pending.then_some(command(token)))
        .collect();
    let last = commands.last().copied();
    for &token in commands.iter().filter(|token| !pending.contains(token)) {
        let result = if Some(token) == last {
            device_result(done.status)
        } else {
            Outcome::Complete
        };
        w.rec.terminal(token, result);
    }
    let still_held = in_use(arena);
    for &taken in done.buffers.iter().filter(|b| !still_held.contains(b)) {
        w.rec.release(buffer(taken), Custodian::Storage);
    }
    w.duplicate_returned(at);
    Some(done.ticks)
}

/// Publishes `payload` under `object` and records the publication with
/// the slot and extent production placed it in.
fn published<'s>(
    w: &mut Watch,
    storage: &'s Storage<TestPlatform>,
    device: &mut Device<'s, '_>,
    object: &Key,
    owner: (KeyId, Label),
    payload: &[u8],
) -> (u32, u64) {
    publish(storage, device, object, META, payload);
    w.published((storage, device), object, owner, payload)
}

/// Looks `object` up under a fresh registration and, on a hit, reads the
/// `len`-byte payload back, drops the lease and records its credit
/// returned.
fn read_back<'s>(
    w: &mut Watch,
    (storage, device, arena): (
        &'s Storage<TestPlatform>,
        &mut Device<'s, '_>,
        &BufferArena<TestPlatform>,
    ),
    object: &Key,
    owner: (KeyId, Label),
    len: usize,
) {
    let mut reader = storage.register().expect("a registration");
    if let Some((lease, op)) = w.lookup(storage, &mut reader, object, owner) {
        delivered(w, (device, arena), &lease, (op, owner, len), None);
        w.returned(lease);
    }
}

/// Production acknowledges an invalidation of an absent key, so a slot moves
/// to grace only under the identity production's `removed` report names.
fn removed(
    w: &mut Watch,
    storage: &Storage<TestPlatform>,
    (object, key): (&Key, KeyId),
) -> Option<(u32, u64)> {
    let invalidation = invalidate(storage, object).ok()?;
    w.rec.invalidate(key, Outcome::Acknowledged);
    let (id, _) = invalidation.removed?;
    let retired = identity(id);
    w.retired(retired);
    Some(retired)
}

/// Whether production's ledger holds no retired slot, so grace ended for
/// every invalidated publication.
fn grace_empty(storage: &Storage<TestPlatform>) -> bool {
    storage
        .pool_report()
        .and_then(|report| report.ledger)
        .is_some_and(|ledger| ledger.slots.retired == 0)
}

fn exact_read(id: u16) -> Vec<Row> {
    let (storage, arena) = (storage(8), arena(4));
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::in_episode(&storage, id);
    let (object, payload) = (key(1), generated(K, A, SMALL));
    published(&mut w, &storage, &mut device, &object, (K, A), &payload);
    read_back(
        &mut w,
        (&storage, &mut device, &arena),
        &object,
        (K, A),
        SMALL,
    );
    w.rec.rows().to_vec()
}

fn acknowledged_invalidation(id: u16) -> Vec<Row> {
    let (storage, arena) = (storage(8), arena(4));
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::in_episode(&storage, id);
    let object = key(1);
    let payload = generated(K, A, SMALL);
    published(&mut w, &storage, &mut device, &object, (K, A), &payload);
    removed(&mut w, &storage, (&object, K));
    let mut fresh = storage.register().expect("a registration");
    if let Some((lease, _)) = w.lookup(&storage, &mut fresh, &object, (K, A)) {
        w.returned(lease);
    }
    w.rec.rows().to_vec()
}

/// Two objects publish, one is invalidated and reclaimed, and its key
/// publishes again into the freed slot; the kept object is then read
/// twice, so its second read takes a response buffer and a read command
/// the first returned.
fn reclaimed_extent_reuse(id: u16) -> Vec<Row> {
    let (storage, arena) = (storage(8), arena(4));
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::in_episode(&storage, id);
    let (first, kept) = (key(1), key(2));
    let payload = generated(K, A, SMALL);
    published(&mut w, &storage, &mut device, &first, (K, A), &payload);
    let held_payload = generated(KEEP, B, SMALL);
    published(
        &mut w,
        &storage,
        &mut device,
        &kept,
        (KEEP, B),
        &held_payload,
    );
    let retired = removed(&mut w, &storage, (&first, K));
    device.persist_journal();
    drain(&storage);
    for _ in 0..FUNDED {
        let _ = storage.maintain(&mut budget());
    }
    if let Some(retired) = retired
        && grace_empty(&storage)
    {
        w.reclaimed(retired, (K, A));
    }
    let next = generated(K, C, SMALL);
    published(&mut w, &storage, &mut device, &first, (K, C), &next);
    for _ in 0..2 {
        read_back(
            &mut w,
            (&storage, &mut device, &arena),
            &kept,
            (KEEP, B),
            SMALL,
        );
    }
    w.rec.rows().to_vec()
}

/// An object publishes, is read once and invalidated, and grace ends; each
/// step records production's pool, ledger and table reports, and the run
/// ends at a released checkpoint, where every counted resource must have
/// returned.
fn released_read(id: u16) -> Vec<Row> {
    let (storage, arena) = (storage(8), arena(4));
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::in_episode(&storage, id);
    let object = key(1);
    let payload = generated(K, A, SMALL);
    published(&mut w, &storage, &mut device, &object, (K, A), &payload);
    w.reports(&storage, &arena, &device.volume);
    let mut reader = storage.register().expect("a registration");
    if let Some((lease, op)) = w.lookup(&storage, &mut reader, &object, (K, A)) {
        w.reports(&storage, &arena, &device.volume);
        delivered(
            &mut w,
            (&mut device, &arena),
            &lease,
            (op, (K, A), SMALL),
            None,
        );
        w.reports(&storage, &arena, &device.volume);
        w.returned(lease);
    }
    drop(reader);
    w.reports(&storage, &arena, &device.volume);
    if let Some(retired) = removed(&mut w, &storage, (&object, K)) {
        device.persist_journal();
        drain(&storage);
        if grace_empty(&storage) {
            w.reclaimed(retired, (K, A));
        }
    }
    w.reports(&storage, &arena, &device.volume);
    w.rec.checkpoint(Checkpoint::Released);
    w.rec.rows().to_vec()
}

/// A published object is invalidated; funded maintenance must end its
/// grace and a fresh publication must then serve an exact hit, all within
/// [`FUNDED`] actions.
fn funded_reclaim(id: u16) -> Vec<Row> {
    let (storage, arena) = (storage(8), arena(4));
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::in_episode(&storage, id);
    let object = key(1);
    let payload = generated(K, A, SMALL);
    published(&mut w, &storage, &mut device, &object, (K, A), &payload);
    let retired = removed(&mut w, &storage, (&object, K));
    device.persist_journal();
    let mut funded = 0;
    if let Some(retired) = retired {
        // Grace is read after the last funded call too, so the history
        // records every grace end production reached within the budget.
        loop {
            if grace_empty(&storage) {
                w.reclaimed(retired, (K, A));
                break;
            }
            if funded == FUNDED {
                break;
            }
            funded += 1;
            let _ = storage.maintain(&mut budget());
        }
    }
    let (next, payload) = (key(2), generated(NEXT, B, SMALL));
    let mut publication = false;
    while !publication && funded <= FUNDED {
        funded += 1;
        if let Ok(mut fill) = reserve(&storage, &next, META, SMALL - META) {
            device.fill(&mut fill, &payload);
            publication = fill
                .publish(&mut device.volume, u64::MAX, TRIES, &mut budget())
                .is_ok();
        }
    }
    w.rec.checkpoint(Checkpoint::Qualified {
        funded,
        limit: FUNDED,
    });
    if publication {
        w.published((&storage, &device), &next, (NEXT, B), &payload);
        read_back(
            &mut w,
            (&storage, &mut device, &arena),
            &next,
            (NEXT, B),
            SMALL,
        );
    }
    w.rec.rows().to_vec()
}

/// The index the failed owner's resources are recorded under, so its
/// commands and buffers stay distinct from the healthy owner's, which come
/// from another table and arena.
const FAILED_OWNER: u32 = 1 << 16;

fn of_failed((kind, index, incarnation): (ResourceKind, u32, u64)) -> (ResourceKind, u32, u64) {
    (kind, FAILED_OWNER + index, incarnation)
}

/// Owner A fails holding a read: its command never terminates and its
/// close stays unproven, so A retains the command and the response buffer.
/// Owner B, over its own storage and disk, serves an exact read while A's
/// volume is ticked beside it each turn. A then attempts the integrator's
/// release, which its unproven stop must refuse. A retained resource that
/// production frees is recorded returned.
fn failed_owner_beside_healthy(id: u16) -> Vec<Row> {
    let (failed_storage, failed_arena) = (storage(8), arena(4));
    let (healthy_storage, healthy_arena) = (storage(8), arena(4));
    let mut failed = Device::new(&failed_storage, &failed_arena);
    let mut healthy = Device::new(&healthy_storage, &healthy_arena);
    let mut w = Watch::in_episode(&healthy_storage, id);
    let (held_object, served) = (key(1), key(2));
    let held_payload = generated(K, A, SMALL);
    publish(
        &failed_storage,
        &mut failed,
        &held_object,
        META,
        &held_payload,
    );
    let mut failed_reader = failed_storage.register().expect("a registration");
    let failed_lease = failed_reader
        .lookup(&held_object, TRIES, &mut budget())
        .ok();
    let before = in_use(&failed_arena);
    let failed_read = failed_lease
        .as_ref()
        .and_then(|lease| failed.volume.read(lease.duplicate(), u64::MAX).ok());
    let token = failed_read.and(last_read(&failed.control));
    let retained: Vec<_> = in_use(&failed_arena).difference(&before).copied().collect();
    if let Some(token) = token {
        failed.control.hold(token);
        w.rec
            .take(of_failed(command(token)), Custodian::Storage, None);
    }
    for &taken in &retained {
        w.rec
            .take(of_failed(buffer(taken)), Custodian::Storage, None);
    }
    failed.control.set_quiesce(QuiesceMode::Unproven);
    let stop = failed.volume.close();
    if let Some(token) = token {
        w.rec.isolated(of_failed(command(token)));
    }
    for &taken in &retained {
        w.rec.isolated(of_failed(buffer(taken)));
    }
    let payload = generated(KEEP, B, SMALL);
    published(
        &mut w,
        &healthy_storage,
        &mut healthy,
        &served,
        (KEEP, B),
        &payload,
    );
    let checkpoint = w.rec.checkpoint(Checkpoint::Healthy {
        turns: 0,
        bound: SERVE_BOUND,
    });
    let mut reader = healthy_storage.register().expect("a registration");
    let mut turns = TICKS as u32;
    if let Some((lease, op)) = w.lookup(&healthy_storage, &mut reader, &served, (KEEP, B)) {
        let ended = delivered(
            &mut w,
            (&mut healthy, &healthy_arena),
            &lease,
            (op, (KEEP, B), SMALL),
            Some(&mut failed),
        );
        turns = ended.unwrap_or(turns);
        w.returned(lease);
    }
    // The integrator's release step: an unproven stop must refuse it and
    // keep the volume, its command and its buffer.
    let Device {
        volume,
        control: failed_control,
    } = failed;
    let kept = volume.release().err();
    let pending = kept
        .as_ref()
        .map_or(Vec::new(), |kept| kept.0.table_tokens());
    if let Some(token) = token
        && !pending.iter().any(|&(held, live)| held == token && live)
    {
        w.rec.terminal(
            of_failed(command(token)),
            Outcome::Damaged(Failure::Quiesced),
        );
    }
    let still_held = in_use(&failed_arena);
    for &taken in &retained {
        if !still_held.contains(&taken) {
            w.rec.release(of_failed(buffer(taken)), Custodian::Storage);
        }
    }
    let mut rows = w.rec.rows().to_vec();
    // The checkpoint row precedes the healthy read it judges, so it is
    // recorded first and given the turns the read took once it ended.
    if let Some(row) = rows.iter_mut().find(|row| row.op == checkpoint) {
        row.checkpoint = Some(Checkpoint::Healthy {
            turns,
            bound: SERVE_BOUND,
        });
    }
    drop((kept, failed_control, stop, failed_lease, failed_reader));
    rows
}

/// An object whose second chunk carries one damaged sector: the read must
/// end in that chunk's mismatch after exactly the verified first chunk.
fn damaged_later_chunk(id: u16) -> Vec<Row> {
    let (storage, arena) = (storage(8), arena(4));
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::in_episode(&storage, id);
    let (object, payload) = (key(1), generated(K, A, PAYLOAD));
    let at = published(&mut w, &storage, &mut device, &object, (K, A), &payload);
    let locator = storage.live_pool().expect("a live pool").records()[at.0 as usize].locator();
    let start = super::volume_fixture::device_byte(&storage, locator) as u64;
    let second = (RECORD.chunk + 512) as u64;
    device.control.damage(start + second, 512);
    read_back(
        &mut w,
        (&storage, &mut device, &arena),
        &object,
        (K, A),
        PAYLOAD,
    );
    w.rec.rows().to_vec()
}

/// The first complete delivery's first byte flipped: a wrong prefix.
fn wrong_byte(mut rows: Vec<Row>) -> (Vec<Row>, OpId) {
    let delivery = rows
        .iter_mut()
        .find(|row| row.kind == ActionKind::Deliver && row.outcome == Some(Outcome::Complete))
        .expect("a complete delivery");
    delivery.payload.as_mut().expect("a payload")[0] ^= 1;
    let op = delivery.op;
    (rows, op)
}

/// The fresh lookup after the acknowledged invalidation answers the removed
/// label: a stale publication.
fn stale_hit(mut rows: Vec<Row>) -> (Vec<Row>, OpId) {
    let invalidated = rows
        .iter()
        .position(|row| row.kind == ActionKind::Invalidate)
        .expect("the invalidation");
    let lookup = rows[invalidated..]
        .iter_mut()
        .find(|row| row.kind == ActionKind::Lookup)
        .expect("the fresh lookup");
    lookup.outcome = Some(Outcome::Hit);
    lookup.label = Some(A);
    lookup.clock = Some(ClockSample::Seconds(1));
    let op = lookup.op;
    (rows, op)
}

/// The last extent taken is recorded over the kept object's extent: an
/// early reuse of a held extent.
fn overlapping_extent(mut rows: Vec<Row>) -> (Vec<Row>, OpId) {
    let spans: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            row.kind == ActionKind::Take
                && row.span.is_some()
                && row
                    .resource()
                    .is_some_and(|r| r.kind == ResourceKind::Extent)
        })
        .map(|(at, _)| at)
        .collect();
    let (kept, last) = (spans[1], spans[spans.len() - 1]);
    rows[last].span = rows[kept].span;
    let op = rows[last].op;
    (rows, op)
}

/// A ledger report of the credits production counts.
fn credit_report(row: &Row) -> bool {
    row.report
        .is_some_and(|report| report.kind == ReportKind::Ledger)
        && row
            .resource()
            .is_some_and(|r| r.kind == ResourceKind::Credit)
}

/// The lease's credit return goes unrecorded: a lost credit, which the next
/// credit report contradicts.
fn lost_credit(mut rows: Vec<Row>) -> (Vec<Row>, OpId) {
    let returned = rows
        .iter()
        .position(|row| {
            row.kind == ActionKind::Release
                && row
                    .resource()
                    .is_some_and(|r| r.kind == ResourceKind::Credit)
        })
        .expect("the credit's return");
    rows.remove(returned);
    let op = rows[returned..]
        .iter()
        .find(|row| credit_report(row))
        .expect("a later credit report")
        .op;
    (rows, op)
}

/// The funded interval is recorded one action past its bound.
fn over_budget(mut rows: Vec<Row>) -> (Vec<Row>, OpId) {
    let row = rows
        .iter_mut()
        .find(|row| matches!(row.checkpoint, Some(Checkpoint::Qualified { .. })))
        .expect("the qualified checkpoint");
    row.checkpoint = Some(Checkpoint::Qualified {
        funded: FUNDED + 1,
        limit: FUNDED,
    });
    let op = row.op;
    (rows, op)
}

/// The healthy owner's interval is recorded one turn past its bound: the
/// failed owner blocked its healthy peer.
fn blocked_peer(mut rows: Vec<Row>) -> (Vec<Row>, OpId) {
    let row = rows
        .iter_mut()
        .find(|row| matches!(row.checkpoint, Some(Checkpoint::Healthy { .. })))
        .expect("the healthy checkpoint");
    row.checkpoint = Some(Checkpoint::Healthy {
        turns: SERVE_BOUND + 1,
        bound: SERVE_BOUND,
    });
    let op = row.op;
    (rows, op)
}

/// The damaged chunk's bytes follow the verified prefix: prohibited bytes
/// past the typed rejection.
fn failed_chunk_bytes(mut rows: Vec<Row>) -> (Vec<Row>, OpId) {
    let delivery = rows
        .iter_mut()
        .find(|row| {
            row.kind == ActionKind::Deliver
                && matches!(
                    row.outcome,
                    Some(Outcome::Damaged(Failure::ChunkMismatch { .. }))
                )
        })
        .expect("a damaged delivery");
    let payload = delivery.payload.as_mut().expect("a payload");
    let more = generated(K, A, PAYLOAD)[payload.len()..payload.len() + 1].to_vec();
    payload.extend_from_slice(&more);
    let op = delivery.op;
    (rows, op)
}

fn has(rows: &[Row], found: impl Fn(&Row) -> bool) -> bool {
    rows.iter().any(found)
}

fn resource_is(row: &Row, kind: ResourceKind) -> bool {
    row.resource().is_some_and(|r| r.kind == kind)
}

fn acknowledged_invalidation_row(row: &Row) -> bool {
    row.kind == ActionKind::Invalidate && row.outcome == Some(Outcome::Acknowledged)
}

/// A complete delivery.
fn complete_read(rows: &[Row]) -> bool {
    has(rows, |row| {
        row.kind == ActionKind::Deliver && row.outcome == Some(Outcome::Complete)
    })
}

/// An acknowledged invalidation followed by a lookup.
fn lookup_after_invalidation(rows: &[Row]) -> bool {
    rows.iter()
        .position(acknowledged_invalidation_row)
        .is_some_and(|at| has(&rows[at..], |row| row.kind == ActionKind::Lookup))
}

/// An ended grace, and a slot, a response buffer and a read command each
/// taken under two incarnations.
fn reclaim_and_reuse(rows: &[Row]) -> bool {
    let reused = |kind: ResourceKind| {
        let takes: Vec<_> = rows
            .iter()
            .filter(|row| row.kind == ActionKind::Take && resource_is(row, kind))
            .map(|row| (row.resource().map(|r| r.index), row.incarnation))
            .collect();
        takes
            .iter()
            .any(|&(index, at)| takes.iter().any(|&(i, a)| i == index && a != at))
    };
    has(rows, |row| row.cause == Some(VisibilityCause::GraceEnd))
        && reused(ResourceKind::Slot)
        && reused(ResourceKind::Buffer)
        && reused(ResourceKind::Command)
}

/// A credit report after the credit's return, then an acknowledged
/// invalidation before the released checkpoint.
fn released_reports(rows: &[Row]) -> bool {
    let returned = rows
        .iter()
        .position(|row| row.kind == ActionKind::Release && resource_is(row, ResourceKind::Credit));
    let released = rows
        .iter()
        .position(|row| row.checkpoint == Some(Checkpoint::Released));
    match (returned, released) {
        (Some(returned), Some(released)) => {
            has(&rows[returned..], credit_report)
                && has(&rows[returned..released], acknowledged_invalidation_row)
        }
        _ => false,
    }
}

fn funded_recovery(rows: &[Row]) -> bool {
    let Some(qualified) = rows
        .iter()
        .position(|row| matches!(row.checkpoint, Some(Checkpoint::Qualified { .. })))
    else {
        return false;
    };
    rows[..qualified]
        .iter()
        .position(acknowledged_invalidation_row)
        .is_some_and(|at| {
            has(&rows[at..qualified], |row| {
                row.cause == Some(VisibilityCause::GraceEnd)
            })
        })
}

/// The failed owner's retained command and buffer, the healthy owner's
/// checkpoint and its complete delivery.
fn retained_beside_healthy(rows: &[Row]) -> bool {
    let isolated = |kind: ResourceKind| {
        has(rows, |row| {
            row.checkpoint == Some(Checkpoint::Isolated) && resource_is(row, kind)
        })
    };
    isolated(ResourceKind::Command)
        && isolated(ResourceKind::Buffer)
        && has(rows, |row| {
            matches!(row.checkpoint, Some(Checkpoint::Healthy { .. }))
        })
        && complete_read(rows)
}

/// A delivery ended by the mismatch of the damaged second chunk.
fn second_chunk_mismatch(rows: &[Row]) -> bool {
    has(rows, |row| {
        row.kind == ActionKind::Deliver
            && row.outcome == Some(Outcome::Damaged(Failure::ChunkMismatch { index: 1 }))
    })
}

#[test]
fn every_live_obligation_has_one_strength_episode_and_restart_has_none() {
    for spec in &OBLIGATIONS {
        let rows = STRENGTH
            .iter()
            .filter(|s| s.obligation == spec.obligation)
            .count();
        let live = spec.evidence.contains(&EvidenceLabel::Live);
        assert_eq!(rows, usize::from(live), "{}", spec.alias);
    }
    assert_eq!(
        OBLIGATIONS[Obligation::Restart as usize].evidence,
        [EvidenceLabel::Abstract, EvidenceLabel::Qualified]
    );
    let mut ids: Vec<u16> = STRENGTH.iter().map(|s| s.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), STRENGTH.len(), "distinct episodes");
}

#[test]
fn an_exact_read_passes_and_a_wrong_byte_fails_o_bytes() {
    attributed(Obligation::Bytes);
}

#[test]
fn an_acknowledged_invalidation_passes_and_a_stale_hit_fails_o_history() {
    attributed(Obligation::History);
}

#[test]
fn a_reclaimed_extent_reuse_passes_and_an_overlapping_extent_fails_o_custody() {
    attributed(Obligation::Custody);
}

#[test]
fn a_released_read_passes_and_a_lost_credit_fails_o_resources() {
    attributed(Obligation::Resources);
}

#[test]
fn a_funded_reclaim_passes_and_an_over_budget_interval_fails_o_progress() {
    attributed(Obligation::Progress);
}

#[test]
fn a_failed_owner_beside_a_healthy_one_passes_and_a_blocked_peer_fails_o_isolation() {
    attributed(Obligation::Isolation);
}

#[test]
fn a_damaged_later_chunk_passes_and_its_failed_bytes_fail_o_contain() {
    attributed(Obligation::Contain);
}

#[test]
fn a_repeated_invalidation_records_no_second_retirement() {
    let (storage, arena) = (storage(8), arena(4));
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::in_episode(&storage, 1);
    let object = key(1);
    let payload = generated(K, A, SMALL);
    let at = published(&mut w, &storage, &mut device, &object, (K, A), &payload);
    assert_eq!(removed(&mut w, &storage, (&object, K)), Some(at));
    let before = w.rec.rows().len();
    assert_eq!(removed(&mut w, &storage, (&object, K)), None);
    assert!(
        !has(&w.rec.rows()[before..], |row| resource_is(
            row,
            ResourceKind::Slot
        )),
        "a second retirement of the removed slot"
    );
}

#[test]
fn a_funded_interval_without_a_reclaim_lacks_the_progress_premise() {
    let s = strength(Obligation::Progress);
    let unreclaimed: Vec<Row> = (s.run)(s.id)
        .into_iter()
        .filter(|row| row.cause != Some(VisibilityCause::GraceEnd))
        .collect();
    assert!(!(s.premise)(&unreclaimed));
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_damaged_later_chunk_passes_and_its_failed_bytes_fail_o_contain,
    a_failed_owner_beside_a_healthy_one_passes_and_a_blocked_peer_fails_o_isolation,
    a_funded_reclaim_passes_and_an_over_budget_interval_fails_o_progress,
    a_reclaimed_extent_reuse_passes_and_an_overlapping_extent_fails_o_custody,
    a_released_read_passes_and_a_lost_credit_fails_o_resources,
    an_acknowledged_invalidation_passes_and_a_stale_hit_fails_o_history,
    an_exact_read_passes_and_a_wrong_byte_fails_o_bytes,
);
