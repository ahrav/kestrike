//! One warm recovery cycle of a class-bound recovery package over any [`Disk`]. Tenure one fills and reads back a
//! bounded set of objects, captures them, and writes its checkpoint through its own unit commands; the package's fault
//! ends that incarnation; tenure two, a new storage whose index starts empty, attaches the same media under a later
//! session with the warm source that names the checkpoint and a harness-built coverage copy holding an INVALIDATE of
//! [`COVERED`], loads to `Live`, reads every object tenure one filled, and then takes fill reservations.
//!
//! A [`Rig`] supplies the device, the fault and how long one operation may wait. The [`Simulated`] rig runs the cycle
//! over the simulated device in every lane, an uncredited proxy; the SPDK rig of the volume hardware cases runs the
//! same cycle on a bound EBS volume. The caller supplies each tenure's authority, a fixture authority under a session
//! above every earlier one, and the harness builds the shard record and the coverage copy: the same-host restart
//! sequence that mints a recovered tenure's authority and its fenced coverage runs over the simulated reservation card
//! alone, in the takeover history world, so a pass here shows the warm load, the allocator and the coverage check on
//! the device and leaves the restart's record checks, its bump, its Reports and the acknowledgement of the INVALIDATE
//! to that world.
//!
//! [`judge`] holds a cycle to the retained set S, every captured object other than [`COVERED`], the object the
//! fixture's INVALIDATE names; S is fixed by the workload whatever coverage copy a treatment builds. Each member of S
//! is served its exact bytes, the covered object misses, the load omits exactly one entry and installs every member of
//! S, and fill reservations occupy units disjoint from the served objects' units. A miss of a member of S fails
//! retention whatever else served, so a cold attach, which serves nothing, fails.
//!
//! Once its fill reservations drop, tenure two takes its residual inventory from the pool report: the filling slots,
//! reserved bytes, pending marks, escrowed units and quarantined slots, each against a zero baseline, the resident
//! slots against the entries the load installed, and the retired slots against the fill reservations the cycle
//! dropped. `judge` requires every residual to read zero. The retired bytes of the dropped reservations and the pool's
//! waste are printed beside the residuals. [`witness`], [`residuals`] and
//! [`persisted`] format the three lines each hardware case prints and the package profiles declare, in the shapes
//! `scripts/recovery-packages.py` parses; `scripts/recovery-package-lines.json` holds one fixed instance of each
//! line, which the formatters and the package judge's tests both read.

use std::time::{Duration, Instant};

use super::super::super::checkpoint::{PossiblyNamed, StagedCheckpoint};
use super::super::super::device::sim::{Media, QuiesceMode, SimControl, media};
use super::super::super::ledger::EngineBudget;
use super::super::super::lookup::LookupError;
use super::super::super::lookup_tests::lookup;
use super::super::super::publication_tests::{DEADLINE, payload as with_metadata, reserved};
use super::super::super::publish_tests::{TRIES, budget, key};
use super::super::super::record::Crc32c;
use super::super::super::recovery::capture_tests::drain;
use super::super::super::recovery::checkpoint::Checkpoint;
use super::super::super::recovery::session_at;
use super::super::super::store_tests::{record, shard};
use super::super::super::test_platform::TestPlatform;
use super::super::super::volume_fixture::{
    BUFFER, MEDIA, ample_io, attach_under, close_and_release, device_byte, fenced, open_stepping,
    pools_with, record_bytes, step,
};
use super::super::super::{
    BufferArena, Disk, ExtentLease, MetadataOutcome, QuiesceStatus, Quiesced, ReadEvent,
    ReadStatus, ReserveError, ServingAuthority, Storage, Volume, WorkBudget,
};
use super::super::checkpoint::UnitDone;
use super::sim_tests::{layout, storage};
use super::tests::live;
use super::{HOLD_SKIPS_RESTORE, WarmSource};
use crate::failover::records::{Ancestry, NamedCheckpoint, ShardRecord};
use crate::index::ShardIndex;
use crate::net::ownership::ShardGeneration;

/// Tenure one fills objects `1..=OBJECTS`, keyed [`key`].
pub(crate) const OBJECTS: u8 = 24;
/// The object the fixture's INVALIDATE names, which the warm treatment's coverage copy holds.
pub(crate) const COVERED: u8 = 5;
/// The capture identity tenure one's checkpoint carries.
const CAPTURE: u32 = 9;
/// A byte of a record's header, which the record's checks cover.
const HEADER_BYTE: usize = 8;
/// The controller-reset hardware case, whose profile `cr1-controller-reset` declares the witnesses this module formats.
const RESET_CASE: &str = "storage::device::spdk::hardware_tests::warm_cycle::a_controller_reset_after_a_quiesced_close_keeps_the_retained_set_warm";
/// The process-kill hardware case, whose profile `pk1-process-kill` declares the witnesses this module formats.
const KILL_CASE: &str = "storage::device::spdk::hardware_tests::warm_cycle::a_killed_owner_keeps_the_retained_set_warm_for_its_restart";

/// Object `n`'s payload: four metadata bytes, the key's first four, then a 40-byte body of `n`.
pub(crate) fn payload(n: u8) -> Vec<u8> {
    with_metadata(&key(n), &[n; 40])
}

/// S: the captured objects other than [`COVERED`], in key order.
fn eligible() -> Vec<u8> {
    (1..=OBJECTS).filter(|&n| n != COVERED).collect()
}

pub(crate) fn arena_on<P: super::super::super::Platform>(platform: P) -> BufferArena<P> {
    pools_with(platform, (4, BUFFER), (9, BUFFER), BUFFER, 2)
}

/// A tenure's volume over the rig's driver.
pub(crate) type RigVolume<'s, 'a, D> = Volume<'s, 'a, TestPlatform, D>;

/// How long one operation of the cycle waits before the cycle fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Patience {
    /// At most this many device steps, for a device whose commands progress only on its steps.
    Polls(usize),
    /// Until this much wall time has passed, for a device whose commands complete in real time.
    Wall(Duration),
}

impl Patience {
    /// Whether the operation may take another step after `polls` steps over `elapsed`.
    pub(crate) fn allows(self, polls: usize, elapsed: Duration) -> bool {
        match self {
            Self::Polls(most) => polls < most,
            Self::Wall(most) => elapsed < most,
        }
    }
}

/// The class-bound recovery package whose fault ends tenure one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The volume closes and releases its driver, and the controller is disabled until the driver proves the
    /// stop.
    ControllerReset,
    /// The process-kill control: the owner's incarnation ends without quiesce, its volume attached.
    ProcessDeath,
}

/// The device and the fault of one recovery package.
pub(crate) trait Rig<'a> {
    type Disk: Disk;

    /// How long each operation of the cycle waits on this rig's device.
    const PATIENCE: Patience;

    /// Attaches `storage`'s volume over a fresh driver of the rig's media under `authority`.
    fn attach<'s>(
        &mut self,
        storage: &'s Storage<TestPlatform>,
        authority: ServingAuthority,
    ) -> RigVolume<'s, 'a, Self::Disk>;

    /// Runs the device and then the volume once, collecting the volume's read events in `out`.
    fn step(&mut self, volume: &mut RigVolume<'_, 'a, Self::Disk>, out: &mut Vec<ReadEvent<'a>>);

    /// The package's fault, which ends tenure one's incarnation after its checkpoint `captured` is written; its index
    /// ends with its storage. A rig whose fault ends the process does not return.
    fn fault(&mut self, volume: RigVolume<'_, 'a, Self::Disk>, captured: Captured);

    /// Closes the recovered tenure's volume and releases its driver.
    fn close(&mut self, volume: RigVolume<'_, 'a, Self::Disk>);
}

/// What tenure one wrote before its fault: the checkpoint and how many entries it captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Captured {
    pub(crate) named: NamedCheckpoint,
    pub(crate) entries: usize,
}

impl Captured {
    /// The report line a tenure that runs in another process prints, which [`parse`](Self::parse) reads back.
    pub(crate) fn line(&self) -> String {
        let NamedCheckpoint {
            slot,
            session,
            capture,
            units,
        } = self.named;
        format!(
            "captured slot {slot} session {session} capture {capture} units {units} entries {}",
            self.entries
        )
    }

    /// The value whose [`line`](Self::line) is exactly `line`, or `None` for any other line.
    pub(crate) fn parse(line: &str) -> Option<Self> {
        let mut words = line.strip_prefix("captured ")?.split(' ');
        let mut field = |name: &str| -> Option<u64> {
            (words.next()? == name).then_some(())?;
            words.next()?.parse().ok()
        };
        let slot = u32::try_from(field("slot")?).ok()?;
        let session = field("session")?;
        let capture = u32::try_from(field("capture")?).ok()?;
        let units = u32::try_from(field("units")?).ok()?;
        let entries = usize::try_from(field("entries")?).ok()?;
        let captured = Self {
            named: NamedCheckpoint {
                slot,
                session,
                capture,
                units,
            },
            entries,
        };
        (captured.line() == line).then_some(captured)
    }
}

/// How tenure two treats the record: the warm load, or one of the three controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Treatment {
    /// The warm load: the warm source names the checkpoint and the coverage copy holds the INVALIDATE of
    /// [`COVERED`].
    Warm,
    /// Control: tenure two attaches with no warm source, the treatment of an actual volume loss.
    Cold,
    /// Control: the coverage copy loses the INVALIDATE of [`COVERED`].
    CoverageDropped,
    /// Control: the warm load, with the first fill reservation at `Live` held open across the residual inventory.
    HeldFill,
}

/// The recovered tenure's residual inventory: each measured quantity less what the cycle accounts for, so a leak
/// reads positive and a shortfall reads negative. The resident slots count against the entries the warm load
/// installed, the retired slots against the fill reservations the cycle dropped, and every other quantity against
/// zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Residuals {
    pub(crate) filling: i64,
    pub(crate) reserved_bytes: i64,
    pub(crate) pending_marks: i64,
    pub(crate) escrow_units: i64,
    pub(crate) quarantined: i64,
    pub(crate) resident_slots: i64,
    pub(crate) retired_slots: i64,
}

impl Residuals {
    /// Each residual under the name the residual line prints it with, in the line's order.
    fn named(&self) -> [(&'static str, i64); 7] {
        [
            ("filling", self.filling),
            ("reserved-bytes", self.reserved_bytes),
            ("pending-marks", self.pending_marks),
            ("escrow-units", self.escrow_units),
            ("quarantined", self.quarantined),
            ("resident-slots", self.resident_slots),
            ("retired-slots", self.retired_slots),
        ]
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Retirement {
    pub(crate) bytes: u64,
    pub(crate) waste: u64,
}

/// What tenure two served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Retained {
    /// Objects served their exact bytes, in key order, [`COVERED`] included when it served.
    pub(crate) served: Vec<u8>,
    /// Objects whose read failed the exact-bytes check, each with the status its read ended with: `Complete` marks a
    /// read that completed with other bytes.
    pub(crate) wrong: Vec<(u8, ReadStatus)>,
    /// The bytes of every member of S in `served`.
    pub(crate) bytes: u64,
    /// The payload bytes of every member of S.
    pub(crate) eligible_bytes: u64,
    /// Slot units the warm load found damaged or could not read.
    pub(crate) damaged_units: u32,
    /// Fill reservations taken at `Live` until the payload filled, and those whose units overlap a served object's.
    pub(crate) reserved: usize,
    pub(crate) overlapping: usize,
    /// From the start of tenure two's attach to the end of its first exact read.
    pub(crate) first_hit: Option<Duration>,
    /// The warm load's omitted and installed entries. `omitted` also counts an entry whose portable deadline lies at or
    /// below the earliest bound of the load's reading, less one second on a stepped scale; any other entry the load
    /// reads expired counts in `installed`.
    pub(crate) omitted: u64,
    pub(crate) installed: u64,
    pub(crate) session: u64,
    pub(crate) checkpoint_session: u64,
    /// The inventory taken once the fill reservations dropped, before the reader and the volume close.
    pub(crate) residuals: Residuals,
    pub(crate) retirement: Retirement,
}

/// Tenure one: attaches cold under `authority`, fills [`OBJECTS`] objects and reads each back, captures them, writes
/// the checkpoint, and hands the live volume to the rig's fault.
pub(crate) fn before<'a, R: Rig<'a>>(rig: &mut R, authority: ServingAuthority) -> Captured {
    let storage = storage(1);
    let session = authority.session().get();
    let mut volume = rig.attach(&storage, authority);
    let mut out = Vec::with_capacity(16);
    open(rig, &mut volume, &mut out);
    for n in 1..=OBJECTS {
        let lease = publish(rig, &storage, &mut volume, n, &mut out);
        let (bytes, status) = read(rig, &mut volume, lease, &mut out);
        assert_eq!(status, ReadStatus::Complete, "object {n} reads back");
        assert!(bytes == payload(n), "object {n} reads back exact");
    }
    storage.start_capture(1024, true, 1024).unwrap();
    let entries = drain(&storage);
    assert_eq!(
        entries.len(),
        usize::from(OBJECTS),
        "the pass captures every object"
    );
    let mut possible = PossiblyNamed::new((shard(), session), layout(), None);
    let checkpoint = Checkpoint {
        shard: shard(),
        session,
        capture: CAPTURE,
    };
    let mut stage = StagedCheckpoint::new(
        Crc32c::detect(),
        &mut possible,
        (checkpoint, &entries),
        &EngineBudget::unlimited(),
    )
    .unwrap();
    for unit in 0..stage.units().len() as u32 {
        volume
            .stage_unit_write(&possible, &mut stage, unit)
            .unwrap();
        let done = wait(
            R::PATIENCE,
            &format!("checkpoint unit {unit}'s write"),
            || {
                rig.step(&mut volume, &mut out);
                out.clear();
                volume.take_unit()
            },
        );
        assert_eq!(
            done,
            UnitDone::Written {
                slot: stage.slot(),
                unit
            }
        );
    }
    let captured = Captured {
        named: stage.named(),
        entries: entries.len(),
    };
    drop(out);
    rig.fault(volume, captured);
    captured
}

/// Tenure two: attaches a new storage over the same media under `authority`, as `treatment` builds it, loads,
/// reaches `Live` and reads every object tenure one filled.
pub(crate) fn after<'a, R: Rig<'a>>(
    rig: &mut R,
    mut authority: ServingAuthority,
    captured: Captured,
    treatment: Treatment,
) -> Retained {
    let storage = storage(1);
    let (session, generation) = (
        authority.session().get(),
        authority.session().generation().get(),
    );
    assert!(
        session > captured.named.session,
        "the recovered tenure's session is above the checkpoint's"
    );
    let coverage = match treatment {
        Treatment::Warm | Treatment::HeldFill => Some(fenced(&[key(COVERED)])),
        Treatment::CoverageDropped => Some(fenced(&[])),
        Treatment::Cold => None,
    };
    if let Some(coverage) = &coverage {
        let record = ShardRecord {
            generation: ShardGeneration::new(generation).unwrap(),
            checkpoint: Some(captured.named),
            cut: 0,
            ancestry: Ancestry::new(&[]).unwrap(),
            ..record()
        };
        let source = WarmSource::new(&record, layout(), authority.session(), coverage);
        authority.warm = source.map(Box::new);
        assert!(authority.warm.is_some(), "the record names the checkpoint");
    }
    let eligible = eligible();
    let eligible_bytes = eligible.iter().map(|&n| payload(n).len() as u64).sum();
    let started = Instant::now();
    let mut volume = rig.attach(&storage, authority);
    let mut out = Vec::with_capacity(16);
    match coverage {
        None => open(rig, &mut volume, &mut out),
        Some(_) => {
            wait(R::PATIENCE, "the warm load", || {
                if volume.readiness().initializing() {
                    rig.step(&mut volume, &mut out);
                    out.clear();
                }
                (!volume.readiness().initializing()).then_some(())
            });
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Open,
                "the warm load commits: {:?}",
                volume.recovery_report().warm
            );
            live(&storage, &mut volume);
        }
    }
    let warm = volume.recovery_report().warm;
    let damaged_units = warm.failed_units + warm.unread_units;
    let mut retained = Retained {
        eligible_bytes,
        served: Vec::new(),
        wrong: Vec::new(),
        bytes: 0,
        damaged_units,
        reserved: 0,
        overlapping: 0,
        first_hit: None,
        omitted: warm.omitted,
        installed: warm.installed,
        session,
        checkpoint_session: captured.named.session,
        residuals: Residuals::default(),
        retirement: Retirement::default(),
    };
    let mut reader = storage.register().unwrap();
    let mut held = Vec::new();
    for n in 1..=OBJECTS {
        match lookup(&mut reader, &key(n), 4) {
            Ok(lease) => {
                let locator =
                    storage.live_pool().unwrap().records()[lease.id().slot_index()].locator();
                let (bytes, status) = read(rig, &mut volume, lease, &mut out);
                if status == ReadStatus::Complete && bytes == payload(n) {
                    retained.first_hit.get_or_insert_with(|| started.elapsed());
                    if eligible.contains(&n) {
                        retained.bytes += bytes.len() as u64;
                    }
                    retained.served.push(n);
                    held.push(units(locator));
                } else {
                    retained.wrong.push((n, status));
                }
            }
            Err(LookupError::Missing) => {}
            Err(other) => panic!("object {n}: {other:?}"),
        }
    }
    let mut reservations = Vec::new();
    loop {
        match storage.reserve(Some(0), Some(100), &mut WorkBudget::new(1 << 20)) {
            Ok(reservation) => {
                let (start, end) = units(reservation.locator());
                retained.overlapping +=
                    usize::from(held.iter().any(|&(s, e)| s < end && start < e));
                reservations.push(reservation);
            }
            Err(
                ReserveError::PayloadFull
                | ReserveError::ObjectSlotsFull
                | ReserveError::CleanReserve,
            ) => {
                break;
            }
            Err(other) => panic!("a fill reservation at Live: {other:?}"),
        }
        assert!(reservations.len() <= 256, "the payload fills");
    }
    retained.reserved = reservations.len();
    let held_fill = match treatment {
        Treatment::HeldFill => reservations.drain(..1).next(),
        Treatment::Warm | Treatment::Cold | Treatment::CoverageDropped => None,
    };
    let dropped = reservations.len() as u64;
    drop(reservations);
    (retained.residuals, retained.retirement) = inventory(&storage, retained.installed, dropped);
    drop((held_fill, reader, out));
    rig.close(volume);
    retained
}

/// The pool's residuals against the cycle's account, with `installed` the entries the warm load installed, and its
/// retirement counts.
fn inventory(
    storage: &Storage<TestPlatform>,
    installed: u64,
    dropped: u64,
) -> (Residuals, Retirement) {
    let pool = storage.pool_report().expect("a live pool");
    let ledger = pool.ledger.expect("an unpoisoned pool");
    let signed = |value: u64| i64::try_from(value).expect("a ledger count fits i64");
    let residuals = Residuals {
        filling: signed(ledger.slots.filling as u64),
        reserved_bytes: signed(ledger.raw.reserved as u64),
        pending_marks: signed(pool.pending_marks as u64),
        escrow_units: signed(pool.escrow_units),
        quarantined: signed(ledger.slots.quarantined as u64),
        resident_slots: signed(ledger.slots.resident as u64) - signed(installed),
        retired_slots: signed(ledger.slots.retired as u64) - signed(dropped),
    };
    let retirement = Retirement {
        bytes: ledger.raw.retired as u64,
        waste: ledger.raw.waste as u64,
    };
    (residuals, retirement)
}

/// The rule a cycle broke, or `Ok` when tenure two served every member of S its exact bytes, missed the covered
/// object, loaded with exactly one entry omitted and every member of S installed, reserved fills at `Live` only on
/// units disjoint from the served objects' units, and left every residual at zero: `CoveredObjectMisses` when the
/// covered object served, `ExactBytes` when a read returned other bytes, `RetainedSetServed` when a member of S
/// missed, `LoadCounts` when the load omitted other than one entry or installed other than S's size,
/// `DisjointAllocation` when a reservation overlapped a served object's units or zero reservations opened, and
/// `ResidualsZero` when a residual is nonzero. The load's counts show how many entries it omitted; the covered
/// object's miss shows which.
pub(crate) fn judge(retained: &Retained) -> Result<(), &'static str> {
    if retained.served.contains(&COVERED) {
        return Err("CoveredObjectMisses");
    }
    if !retained.wrong.is_empty() {
        return Err("ExactBytes");
    }
    let s = eligible();
    if retained.served != s {
        return Err("RetainedSetServed");
    }
    if retained.omitted != 1 || retained.installed != s.len() as u64 {
        return Err("LoadCounts");
    }
    if retained.overlapping > 0 || retained.reserved == 0 {
        return Err("DisjointAllocation");
    }
    if retained.residuals != Residuals::default() {
        return Err("ResidualsZero");
    }
    Ok(())
}

/// The units `locator` names, as a half-open range.
fn units(locator: super::super::super::ExtentLocator) -> (u64, u64) {
    let start = locator.start_unit();
    (start, start + u64::from(locator.len_units()))
}

/// The retained-set witness line: the members of S served of S's size, the bytes served to members of S, the load's
/// counts, the first hit, the sessions, the fixture legs, and `episode`, the run's episode.
pub(crate) fn witness(retained: &Retained, episode: &str) -> String {
    let s = eligible();
    let members = (retained.served.iter()).filter(|n| s.contains(n)).count();
    let (unaffected, affected) = if retained.damaged_units == 0 {
        (retained.eligible_bytes.to_string(), "0".to_owned())
    } else {
        ("unmeasured".to_owned(), "unmeasured".to_owned())
    };
    format!(
        "retained S {members}/{} bytes {} wrong {} eligible-bytes {} unaffected-bytes {unaffected} affected-bytes {affected} damaged-units {} omitted {} installed {} covered-miss {} reserved {} overlapping {} first-hit-us {} session {:#x} over checkpoint session {:#x} authority fixture coverage harness episode {episode}",
        s.len(),
        retained.bytes,
        retained.wrong.len(),
        retained.eligible_bytes,
        retained.damaged_units,
        retained.omitted,
        retained.installed,
        !retained.served.contains(&COVERED),
        retained.reserved,
        retained.overlapping,
        retained
            .first_hit
            .map_or_else(|| "none".into(), |at| at.as_micros().to_string()),
        retained.session,
        retained.checkpoint_session,
    )
}

/// The residual line reports retirement counts alongside the residuals checked by `judge`.
pub(crate) fn residuals(retained: &Retained) -> String {
    let mut line = String::from("residual");
    for (name, value) in retained.residuals.named() {
        line.push_str(&format!(" {name} {value:+}"));
    }
    let Retirement { bytes, waste } = retained.retirement;
    line.push_str(&format!(" retired-bytes {bytes} waste {waste}"));
    line
}

/// The persisted-checkpoint witness line: tenure one's captured checkpoint, and the entries the warm load installed
/// and omitted from it.
pub(crate) fn persisted(captured: &Captured, retained: &Retained) -> String {
    format!(
        "persisted {} installed {} omitted {}",
        captured.line(),
        retained.installed,
        retained.omitted
    )
}

/// The reset fault witness: the controller's CC and CSTS registers after its disable, and tenure one's checkpoint.
pub(crate) fn reset_witness(cc: u32, csts: u32, captured: &Captured) -> String {
    format!(
        "controller-reset cc {cc:#x} csts {csts:#x} after {}",
        captured.line()
    )
}

/// The kill fault witness: the process SIGKILL ended, and the checkpoint it reported before.
pub(crate) fn kill_witness(pid: u32, captured: &Captured) -> String {
    format!("process-kill signal 9 pid {pid} after {}", captured.line())
}

/// Calls `attempt`, which steps the rig's device once when it yields `None`, until it yields a value.
///
/// # Panics
///
/// With `what` once the rig's [`Patience`] refuses another step.
fn wait<T>(patience: Patience, what: &str, mut attempt: impl FnMut() -> Option<T>) -> T {
    let (started, mut polls) = (Instant::now(), 0);
    while patience.allows(polls, started.elapsed()) {
        if let Some(done) = attempt() {
            return done;
        }
        polls += 1;
    }
    panic!(
        "{what} stayed unfinished after {polls} polls over {:?}",
        started.elapsed()
    )
}

/// Ticks the bootstrap until the volume reaches `Live`, formatting a volume the bootstrap reports `Unformatted`.
fn open<'a, R: Rig<'a>>(
    rig: &mut R,
    volume: &mut RigVolume<'_, 'a, R::Disk>,
    out: &mut Vec<ReadEvent<'a>>,
) {
    let started = Instant::now();
    open_stepping(
        volume,
        |ticks| R::PATIENCE.allows(ticks, started.elapsed()),
        |volume| {
            rig.step(volume, out);
            out.clear();
        },
    );
}

/// Fills object `n`, publishes it, and services both index shards' fills.
fn publish<'s, 'a, R: Rig<'a>>(
    rig: &mut R,
    storage: &'s Storage<TestPlatform>,
    volume: &mut RigVolume<'s, 'a, R::Disk>,
    n: u8,
    out: &mut Vec<ReadEvent<'a>>,
) -> ExtentLease<'s, TestPlatform> {
    let bytes = payload(n);
    let mut fill = reserved(storage, &key(n), &bytes[4..]).expect("a reservation");
    let mut taken = 0;
    wait(R::PATIENCE, &format!("object {n}'s writes"), || {
        let progress = fill.progress(volume);
        assert!(!progress.failed, "every write of object {n} succeeds");
        if progress.is_ready() {
            return Some(());
        }
        // A submit the volume refused leaves its segment staged; a receive of no bytes retries it.
        if let Ok(count) = fill.receive(volume, &bytes[taken..], &mut ample_io()) {
            taken += count;
        }
        rig.step(volume, out);
        out.clear();
        let progress = fill.progress(volume);
        assert!(!progress.failed, "every write of object {n} succeeds");
        progress.is_ready().then_some(())
    });
    let lease = fill
        .publish(volume, DEADLINE, TRIES, &mut budget())
        .expect("published");
    for shard in 0..2 {
        storage
            .service_fills(ShardIndex(shard), 8, &mut WorkBudget::new(1 << 20))
            .unwrap();
    }
    lease
}

/// Reads `lease`'s object to its `Done`, granting each next command after a chunk.
fn read<'s, 'a, R: Rig<'a>>(
    rig: &mut R,
    volume: &mut RigVolume<'s, 'a, R::Disk>,
    lease: ExtentLease<'s, TestPlatform>,
    out: &mut Vec<ReadEvent<'a>>,
) -> (Vec<u8>, ReadStatus) {
    let op = volume.read(lease, u64::MAX).expect("admitted");
    let mut bytes = Vec::new();
    let status = wait(R::PATIENCE, "the read", || {
        rig.step(volume, out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { op: of, chunk, .. } => {
                    assert_eq!(of, op);
                    bytes.extend_from_slice(chunk.bytes());
                    let _ = volume.grant_read(op);
                }
                ReadEvent::Done { op: of, status, .. } => {
                    assert_eq!(of, op);
                    return Some(status);
                }
            }
        }
        None
    });
    (bytes, status)
}

/// What the simulated rig writes over one object's record on the medium between the tenures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Damage {
    /// One byte of the record header flips, so the record's checks refuse the read.
    Header(u8),
    /// A valid record of the same identity and lengths whose body differs, so the read completes with other bytes.
    Body(u8),
}

/// The uncredited proxy rig: one simulated medium every incarnation attaches, the fault it plants, and the damage
/// it writes over one object's record after the fault.
pub(crate) struct Simulated<'a> {
    media: Media,
    arena: &'a BufferArena<TestPlatform>,
    control: Option<SimControl>,
    fault: Fault,
    damage: Option<Damage>,
}

impl<'a> Simulated<'a> {
    pub(crate) fn new(arena: &'a BufferArena<TestPlatform>, fault: Fault) -> Self {
        Self {
            media: media(MEDIA),
            arena,
            control: None,
            fault,
            damage: None,
        }
    }
}

impl<'a> Rig<'a> for Simulated<'a> {
    type Disk = super::super::super::device::sim::SimDisk;

    const PATIENCE: Patience = Patience::Polls(1 << 16);

    fn attach<'s>(
        &mut self,
        storage: &'s Storage<TestPlatform>,
        authority: ServingAuthority,
    ) -> RigVolume<'s, 'a, Self::Disk> {
        let (volume, control) =
            attach_under(storage, self.arena, &self.media, authority).expect("attach");
        self.control = Some(control);
        volume
    }

    fn step(&mut self, volume: &mut RigVolume<'_, 'a, Self::Disk>, out: &mut Vec<ReadEvent<'a>>) {
        step(
            volume,
            self.control.as_ref().expect("an attached disk"),
            out,
        );
    }

    fn fault(&mut self, volume: RigVolume<'_, 'a, Self::Disk>, _: Captured) {
        let written = self.damage.map(|damage| {
            let n = match damage {
                Damage::Header(n) | Damage::Body(n) => n,
            };
            let storage = volume.storage();
            let mut reader = storage.register().unwrap();
            let lease = lookup(&mut reader, &key(n), 4).expect("tenure one holds the object");
            let slot = lease.id().slot_index();
            let pool = storage.live_pool().unwrap();
            let at = device_byte(storage, pool.records()[slot].locator());
            match damage {
                Damage::Header(_) => (
                    at + HEADER_BYTE,
                    vec![self.media.borrow()[at + HEADER_BYTE] ^ 0xFF],
                ),
                Damage::Body(_) => {
                    let session =
                        pool.generations()[slot].load(std::sync::atomic::Ordering::Relaxed);
                    let bytes = payload(n);
                    (
                        at,
                        record_bytes(storage, key(n), lease.id(), session, &bytes[..4], &[!n; 40]),
                    )
                }
            }
        });
        match self.fault {
            Fault::ControllerReset => {
                let control = self.control.as_ref().expect("an attached disk");
                let mut out = Vec::with_capacity(8);
                let (quiesced, mut disk) = close_and_release(
                    volume,
                    |ticks| Self::PATIENCE.allows(ticks, Duration::ZERO),
                    |volume| {
                        step(volume, control, &mut out);
                        out.clear();
                    },
                );
                assert_eq!(
                    quiesced,
                    Quiesced::AllReturned,
                    "every command returned before the disable"
                );
                control.set_quiesce(QuiesceMode::Reset);
                assert_eq!(
                    disk.quiesce(),
                    QuiesceStatus::Stopped,
                    "the disable is proven"
                );
            }
            Fault::ProcessDeath => drop(volume),
        }
        if let Some((at, bytes)) = written {
            self.media.borrow_mut()[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        self.control = None;
    }

    fn close(&mut self, volume: RigVolume<'_, 'a, Self::Disk>) {
        drop(volume);
        self.control = None;
    }
}

/// One cycle over the simulated device under `fault` and `treatment`, with `damage` written over one object's
/// record on the medium between the tenures when it names one. Tenure one serves under session `(3, 2)`, tenure
/// two under `(3, 3)`.
fn cycle(fault: Fault, treatment: Treatment, damage: Option<Damage>) -> (Captured, Retained) {
    let arena = arena_on(TestPlatform::heap(4096));
    let mut rig = Simulated::new(&arena, fault);
    rig.damage = damage;
    let captured = before(&mut rig, ServingAuthority::fixture_under(session_at(3, 2)));
    assert_eq!(Captured::parse(&captured.line()), Some(captured));
    let retained = after(
        &mut rig,
        ServingAuthority::fixture_under(session_at(3, 3)),
        captured,
        treatment,
    );
    (captured, retained)
}

/// A passing cycle's account: every member of S served, the load's counts of the warm treatment, and disjoint
/// reservations.
fn passing() -> Retained {
    Retained {
        served: eligible(),
        wrong: Vec::new(),
        bytes: 44 * eligible().len() as u64,
        eligible_bytes: 44 * eligible().len() as u64,
        damaged_units: 0,
        reserved: 41,
        overlapping: 0,
        first_hit: Some(Duration::from_micros(1)),
        omitted: 1,
        installed: eligible().len() as u64,
        session: 0x3_0000_0003,
        checkpoint_session: 0x3_0000_0002,
        residuals: Residuals::default(),
        retirement: Retirement {
            bytes: 4100,
            waste: 257_032,
        },
    }
}

fn assert_retained(captured: &Captured, retained: &Retained) {
    assert_eq!(judge(retained), Ok(()), "{}", witness(retained, "sim"));
    assert!(retained.first_hit.is_some());
    let bytes = 44 * eligible().len() as u64;
    assert_eq!(
        (
            retained.bytes,
            retained.eligible_bytes,
            retained.damaged_units
        ),
        (bytes, bytes, 0)
    );
    assert!(
        witness(retained, "sim").contains(&format!(
            "wrong 0 eligible-bytes {bytes} unaffected-bytes {bytes} affected-bytes 0 damaged-units 0 "
        )),
        "{}",
        witness(retained, "sim")
    );
    assert!(
        residuals(retained).starts_with(
            "residual filling +0 reserved-bytes +0 pending-marks +0 escrow-units +0 quarantined +0 resident-slots +0 retired-slots +0 retired-bytes "
        ),
        "{}",
        residuals(retained)
    );
    assert_eq!(
        persisted(captured, retained),
        format!("persisted {} installed 23 omitted 1", captured.line())
    );
    eprintln!(
        "{}\n{}\n{}",
        witness(retained, "sim"),
        residuals(retained),
        persisted(captured, retained)
    );
}

/// The controller-reset package's cycle, the uncredited proxy of its hardware case: after a proven
/// controller disable ends tenure one, tenure two loads the checkpoint warm and serves every member of S its exact
/// bytes while the covered object misses, with one entry omitted and every member of S installed.
#[test]
fn a_controller_reset_keeps_the_retained_set_over_the_simulated_device_uncredited() {
    let (captured, retained) = cycle(Fault::ControllerReset, Treatment::Warm, None);
    assert_retained(&captured, &retained);
}

/// The process-kill control of the reboot package, the uncredited proxy of its hardware case: tenure one
/// drops without quiesce, and tenure two loads warm and serves S as after the controller reset.
#[test]
fn a_killed_owner_keeps_the_retained_set_over_the_simulated_device_uncredited() {
    let (captured, retained) = cycle(Fault::ProcessDeath, Treatment::Warm, None);
    assert_retained(&captured, &retained);
}

/// Control: a fill reservation held open across the inventory leaves a filling slot and its reserved bytes, signed
/// positive, so `judge` returns `Err("ResidualsZero")` even when all eligible entries are served.
#[test]
fn control_a_fill_held_past_the_boundary_leaves_a_signed_residual() {
    let (_, retained) = cycle(Fault::ControllerReset, Treatment::HeldFill, None);
    assert_eq!(retained.served, eligible(), "{}", witness(&retained, "sim"));
    assert_eq!(retained.residuals.filling, 1, "{}", residuals(&retained));
    assert!(
        retained.residuals.reserved_bytes > 0,
        "{}",
        residuals(&retained)
    );
    assert!(residuals(&retained).starts_with("residual filling +1 reserved-bytes +"));
    assert_eq!(judge(&retained), Err("ResidualsZero"));
}

/// Control: tenure two attaches with no warm source, so its index starts empty, every member of S misses, and
/// the cycle fails retention by name.
#[test]
fn control_a_cold_attach_after_the_fault_fails_retention() {
    let (_, retained) = cycle(Fault::ProcessDeath, Treatment::Cold, None);
    assert!(retained.served.is_empty(), "{}", witness(&retained, "sim"));
    assert_eq!((retained.omitted, retained.installed), (0, 0));
    assert_eq!(judge(&retained), Err("RetainedSetServed"));
}

/// Control: the coverage copy loses the INVALIDATE, so the load installs the covered object and serves it, and the
/// cycle fails by name.
#[test]
fn control_a_coverage_copy_without_the_invalidate_serves_the_covered_object() {
    let (_, retained) = cycle(Fault::ControllerReset, Treatment::CoverageDropped, None);
    assert!(
        retained.served.contains(&COVERED),
        "{}",
        witness(&retained, "sim")
    );
    assert_eq!(
        (retained.bytes, retained.omitted, retained.installed),
        (44 * eligible().len() as u64, 0, u64::from(OBJECTS)),
        "the served bytes count members of S alone"
    );
    assert_eq!(judge(&retained), Err("CoveredObjectMisses"));
}

/// Control: a byte of object 7's record header flips on the medium between the tenures, so its read ends other than
/// complete, and the cycle fails by name.
#[test]
fn control_a_record_header_flipped_between_the_tenures_fails_exact_bytes() {
    let (_, retained) = cycle(
        Fault::ProcessDeath,
        Treatment::Warm,
        Some(Damage::Header(7)),
    );
    assert!(
        matches!(retained.wrong[..], [(7, status)] if status != ReadStatus::Complete),
        "{:?}: {}",
        retained.wrong,
        witness(&retained, "sim")
    );
    assert_eq!(judge(&retained), Err("ExactBytes"));
}

/// Control: a valid record of object 7's identity and lengths with another body replaces it on the medium between
/// the tenures, so its read completes with other bytes than tenure one wrote, and the cycle fails by name.
#[test]
fn control_a_record_with_another_body_fails_exact_bytes() {
    let (_, retained) = cycle(Fault::ProcessDeath, Treatment::Warm, Some(Damage::Body(7)));
    assert_eq!(
        retained.wrong,
        [(7, ReadStatus::Complete)],
        "{}",
        witness(&retained, "sim")
    );
    assert_eq!(judge(&retained), Err("ExactBytes"));
}

/// Control: the warm load's hold skips restoring the restored extents into the allocator (`HOLD_SKIPS_RESTORE`), so
/// fill reservations at `Live` place over served objects' units, and the cycle fails by name.
#[test]
fn control_reservations_over_restored_units_fail_disjoint_allocation() {
    struct Planted;
    impl Drop for Planted {
        fn drop(&mut self) {
            HOLD_SKIPS_RESTORE.with(|plant| plant.set(false));
        }
    }
    let planted = Planted;
    HOLD_SKIPS_RESTORE.with(|plant| plant.set(true));
    let (_, retained) = cycle(Fault::ControllerReset, Treatment::Warm, None);
    drop(planted);
    assert!(retained.overlapping > 0, "{}", witness(&retained, "sim"));
    assert_eq!(judge(&retained), Err("DisjointAllocation"));
}

/// Each rule fails a passing account changed in that rule's quantity alone, by its name; a passing account passes.
#[test]
fn the_judge_names_each_rule_an_account_breaks() {
    assert_eq!(judge(&passing()), Ok(()));
    let short = |edit: fn(&mut Retained)| {
        let mut retained = passing();
        edit(&mut retained);
        judge(&retained)
    };
    assert_eq!(
        short(|r| r.served.insert(4, COVERED)),
        Err("CoveredObjectMisses")
    );
    assert_eq!(
        short(|r| r.wrong.push((3, ReadStatus::Complete))),
        Err("ExactBytes")
    );
    assert_eq!(
        short(|r| r.wrong.push((3, ReadStatus::Short))),
        Err("ExactBytes")
    );
    assert_eq!(
        short(|r| r.served.truncate(r.served.len() - 1)),
        Err("RetainedSetServed")
    );
    assert_eq!(short(|r| r.omitted = 0), Err("LoadCounts"));
    assert_eq!(short(|r| r.omitted = 2), Err("LoadCounts"));
    assert_eq!(short(|r| r.installed -= 1), Err("LoadCounts"));
    assert_eq!(short(|r| r.installed += 1), Err("LoadCounts"));
    assert_eq!(short(|r| r.overlapping = 1), Err("DisjointAllocation"));
    assert_eq!(short(|r| r.reserved = 0), Err("DisjointAllocation"));
    assert_eq!(short(|r| r.residuals.filling = 1), Err("ResidualsZero"));
    assert_eq!(
        short(|r| r.residuals.resident_slots = -1),
        Err("ResidualsZero")
    );
    assert_eq!(
        short(|r| r.residuals.pending_marks = 1),
        Err("ResidualsZero")
    );
    assert_eq!(
        short(|r| r.residuals.escrow_units = 1),
        Err("ResidualsZero")
    );
    assert_eq!(short(|r| r.residuals.quarantined = 1), Err("ResidualsZero"));
    assert_eq!(
        short(|r| r.residuals.reserved_bytes = 1),
        Err("ResidualsZero")
    );
    assert_eq!(
        short(|r| r.residuals.retired_slots = 1),
        Err("ResidualsZero")
    );
    assert_eq!(short(|r| r.retirement = Retirement::default()), Ok(()));
}

/// The witness counts only members of S as served: a served covered object adds nothing to its numerator.
#[test]
fn the_witness_counts_only_members_of_s() {
    let mut retained = passing();
    retained.served.pop();
    retained.served.insert(4, COVERED);
    let line = witness(&retained, "e");
    assert!(line.starts_with("retained S 22/23 "), "{line}");
    assert!(line.contains(" covered-miss false "), "{line}");
    assert!(
        line.contains(" authority fixture coverage harness "),
        "{line}"
    );
    assert!(line.ends_with(" episode e"), "{line}");
}

#[test]
fn a_damaged_unit_leaves_the_witness_byte_split_unmeasured() {
    let mut retained = passing();
    retained.damaged_units = 1;
    let line = witness(&retained, "e");
    assert!(
        line.contains(" eligible-bytes 1012 unaffected-bytes unmeasured affected-bytes unmeasured damaged-units 1 "),
        "{line}"
    );
}

fn fixture_checkpoint() -> Captured {
    Captured {
        named: NamedCheckpoint {
            slot: 0,
            session: 0x3_0000_0002,
            capture: CAPTURE,
            units: 3,
        },
        entries: usize::from(OBJECTS),
    }
}

fn fixture_lines() -> [(&'static str, String); 5] {
    let captured = fixture_checkpoint();
    [
        ("controller-reset", reset_witness(0x46_0000, 0, &captured)),
        ("process-kill", kill_witness(7, &captured)),
        ("retained", witness(&passing(), "e")),
        ("residual", residuals(&passing())),
        ("persisted", persisted(&captured, &passing())),
    ]
}

#[test]
fn the_formatters_print_the_committed_package_lines() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../scripts/recovery-package-lines.json"
    ))
    .unwrap();
    for (name, line) in fixture_lines() {
        assert_eq!(fixture[name], line.as_str(), "{name}");
    }
    assert_eq!(fixture.as_object().unwrap().len(), 5);
}

#[test]
fn the_witness_prints_each_field_in_its_own_place() {
    let retained = Retained {
        served: vec![1, 2, 3],
        wrong: vec![(6, ReadStatus::Complete), (7, ReadStatus::Short)],
        bytes: 132,
        eligible_bytes: 1012,
        damaged_units: 0,
        reserved: 17,
        overlapping: 4,
        first_hit: Some(Duration::from_micros(2737)),
        omitted: 9,
        installed: 11,
        session: 0x3_0000_0009,
        checkpoint_session: 0x3_0000_0008,
        residuals: Residuals {
            filling: 1,
            reserved_bytes: -2,
            pending_marks: 3,
            escrow_units: -4,
            quarantined: 5,
            resident_slots: -6,
            retired_slots: 7,
        },
        retirement: Retirement {
            bytes: 8,
            waste: 10,
        },
    };
    assert_eq!(
        witness(&retained, "r1"),
        "retained S 3/23 bytes 132 wrong 2 eligible-bytes 1012 unaffected-bytes 1012 affected-bytes 0 damaged-units 0 omitted 9 installed 11 covered-miss true reserved 17 overlapping 4 first-hit-us 2737 session 0x300000009 over checkpoint session 0x300000008 authority fixture coverage harness episode r1"
    );
    assert_eq!(
        residuals(&retained),
        "residual filling +1 reserved-bytes -2 pending-marks +3 escrow-units -4 quarantined +5 resident-slots -6 retired-slots +7 retired-bytes 8 waste 10"
    );
}

/// A wait accepts an operation that finishes on its last allowed step, and names an operation still pending then.
#[test]
fn a_wait_accepts_the_last_allowed_step_and_names_a_pending_operation() {
    let mut steps = 0;
    wait(Patience::Polls(3), "the operation", || {
        steps += 1;
        (steps == 3).then_some(())
    });
    assert_eq!(steps, 3);
    let pending =
        std::panic::catch_unwind(|| wait(Patience::Polls(3), "the warm load", || None::<()>));
    let message = *pending.unwrap_err().downcast::<String>().unwrap();
    assert!(
        message.contains("the warm load stayed unfinished after 3 polls"),
        "{message}"
    );
}

/// A wall-time patience ends only on elapsed time and a poll patience only on its step count.
#[test]
fn patience_ends_on_its_own_measure_alone() {
    let wall = Patience::Wall(Duration::from_secs(10));
    assert!(wall.allows(usize::MAX, Duration::from_secs(9)));
    assert!(!wall.allows(0, Duration::from_secs(10)));
    let polls = Patience::Polls(4);
    assert!(polls.allows(3, Duration::MAX));
    assert!(!polls.allows(4, Duration::ZERO));
}

/// Each package profile declares exactly the witnesses its case prints: the libtest pass line, the fault witness
/// this module formats, the retained-set witness of a passing cycle over the whole of S, the residual line and the
/// persisted line. A change to the workload, the covered object or a witness's wording fails here until the manifest
/// agrees.
#[test]
fn the_package_profiles_declare_the_witnesses_the_cycle_prints() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../scripts/hardware-profiles.json"
    ))
    .unwrap();
    let lines = fixture_lines();
    let printed_line = |name: &str| {
        let (_, line) = lines.iter().find(|(n, _)| *n == name).unwrap();
        format!("observe: {line}")
    };
    for (profile, case, fault) in [
        ("cr1-controller-reset", RESET_CASE, "controller-reset"),
        ("pk1-process-kill", KILL_CASE, "process-kill"),
    ] {
        let declared = &manifest["profiles"][profile]["roles"]["owner"]["cases"][0];
        assert_eq!(declared["id"], case, "{profile} runs {case}");
        let witnesses: Vec<&str> = (declared["witnesses"].as_array().unwrap().iter())
            .map(|witness| witness.as_str().unwrap())
            .collect();
        let printed = [
            format!("test {case} ... ok"),
            printed_line(fault),
            printed_line("retained"),
            printed_line("residual"),
            printed_line("persisted"),
        ];
        assert_eq!(witnesses.len(), printed.len(), "{profile}: {witnesses:?}");
        for line in &printed {
            let matching = witnesses.iter().filter(|w| line.starts_with(**w)).count();
            assert_eq!(matching, 1, "{profile} declares one witness of {line}");
        }
    }
}

/// A report line that names other fields, carries one more word, or spells a number other than as `line` prints
/// it, reads as no capture.
#[test]
fn a_capture_line_parses_only_in_its_own_shape() {
    let captured = Captured {
        named: NamedCheckpoint {
            slot: 1,
            session: 0x3_0000_0006,
            capture: CAPTURE,
            units: 3,
        },
        entries: 24,
    };
    assert_eq!(Captured::parse(&captured.line()), Some(captured));
    assert_eq!(Captured::parse(&format!("{} more", captured.line())), None);
    assert_eq!(
        Captured::parse(&captured.line().replace("units", "unit")),
        None
    );
    assert_eq!(
        Captured::parse(&captured.line().replace("units 3", "units 03")),
        None
    );
    assert_eq!(
        Captured::parse(&captured.line().replace("slot 1", "slot +1")),
        None
    );
    assert_eq!(Captured::parse("entered"), None);
}
