//! The campaign status: one read-only snapshot of a state directory that a
//! monitor polls while a controller runs. It takes no lock and writes
//! nothing. Every record field it reports comes from a record that passed
//! the record read rule and names the job and attempt it is read beside; a
//! record that fails either check appears as a held row carrying `held`,
//! the reason, and `held_code`, the failing step's code. A host fault while
//! reading, such as `EIO` or `EMFILE`, ends the snapshot with an error
//! instead.
//!
//! The snapshot is one JSON object of format [`FORMAT`]:
//!
//! - `format`: [`FORMAT`]; `observed_ms`: the reader's clock when the
//!   snapshot began, in Unix milliseconds; and `state`, the canonical state
//!   path.
//! - `config`: the configuration row `show` prints.
//! - `space`: `free_bytes` and `free_inodes`, the space available to
//!   unprivileged users on the state filesystem.
//! - `probes`: the number of entries under `probes/` that open as
//!   directories, and `held_probes`, a held row naming the `entry` of each
//!   other entry.
//! - `variants`: each distinct count map by its `variant` key, the first 16
//!   hexadecimal digits of the SHA-256 of the map's compact JSON encoding,
//!   keys sorted.
//! - `jobs`: the job rows in `id` order. A verified row carries its `id`;
//!   the experiment's `profile`, `campaign`, `run`, listing `class` and
//!   `attempts_allowed`; the job's `seed`; the admission's `purpose`; the
//!   `build` and `executable` pins; `variant`; `state`; the settlement rows
//!   `result` and `pin`; its `attempts`; and `attempts_held`, a held row
//!   for an attempt history that cannot be listed or has gaps, or for a
//!   settlement record with no attempt history. Jobs with equal `profile`,
//!   `build` and `variant` specify one profile with equal counts on one
//!   build.
//! - A held job row's `id` names its source entry: the suffix-stripped name
//!   of a `jobs/` record, manifest, frozen target bundle or settlement entry, the whole name of a
//!   `jobs/` entry with no job suffix, or the name of an `attempts/` entry
//!   with no job record. Readers parse it as a job identity only when it is
//!   one. One `id` can head a verified row and one or more held rows.
//! - A settlement row carries the settled `attempt` and its finish `class`,
//!   `exit`, `signal` and `watchdog`.
//! - `state` takes the first rule that applies: `held` for a settlement
//!   record with no attempt history; `settled` for a verified result;
//!   `held` for a held result, or a held pin with no result; `settling` for
//!   a verified pin with no result; `held` when `attempts_held` is set or
//!   any attempt row is held; `queued` with no attempt rows; `running` when
//!   the highest-numbered attempt has no finish record; and `waiting` when
//!   it has one. A settled or settling job can still carry held attempt
//!   rows.
//! - Each attempt row carries its `number` and `attempt` identity, in
//!   number order; `intent_ms`, `started_ms` and `finished_ms`, the write
//!   times of its records in Unix milliseconds, null for an absent record
//!   or a time outside the representable range; `finished`, the finish's
//!   `class`, `exit`, `signal`, `watchdog`, `interruption`, `binding`,
//!   `residual_members` and `kernel` counters (`cpu_usage_usec`,
//!   `cpu_throttled_usec`, `cpu_nr_throttled`, and the `memory` and `pids`
//!   event maps); `sim`, the bound artifact's `class`, `command`, `reason`,
//!   `terminal`, `cause`, `identity`, semantic `digest`, `decisions`,
//!   `ledger`, `failure_virtual_us` and `unsuccessful`, the at most 41
//!   bytes of rule an unsuccessful check named; `captured`, true for a
//!   capture marker that matches the finish; and `finding`, the finding the
//!   capture minted. A held attempt row names its directory `entry`.
//! - Reconcile publishes the finish of an attempt interrupted by a
//!   controller restart at recovery, so `finished_ms` minus `started_ms`
//!   includes controller downtime. It publishes both the intent and the
//!   finish of a reservation that never launched at recovery, so
//!   `finished_ms` minus `intent_ms` is near zero and covers recovery work
//!   alone. Neither case adds a field that marks it.
//! - `lock`: the processes that hold the state directory's `flock`, read
//!   without taking the lock, as [`View::lock_holders`] describes. The
//!   holders are read before the job pass; when that read names no
//!   exclusive holder they are read again after the findings, and the
//!   second read is reported, so a controller present at either read is
//!   reported. It is `{"holders": [...]}`, each holder carrying `command`,
//!   the holder's first argument such as `dispatch` or null, `mode`,
//!   `exclusive` for a controller or `shared` for a report snapshot, and
//!   `pid`, null when the table prints zero, a negative number or none. An
//!   empty list means no process visible in the PID namespace of the
//!   procfs at `/proc` holds the lock. It is `{"unknown": reason}` when the
//!   lock table cannot be opened or read other than by a host fault, is no
//!   regular file, or is larger than 1 MiB; a host fault ends the snapshot.
//! - `findings` and `release_blockers`: the listing `findings` prints, with
//!   `held_code` added to each held `triage` object. Retained findings are
//!   read after the jobs.
//!   A verified findings row carries `id`, `verified`, the finding record,
//!   `dispositions`, `resolved`, `blocker` and `triage`: null, a
//!   `{"state": "pending"}` object, a waiting object with `state`, `reason`
//!   and an optional latest result, the latest step's object, or a held
//!   object. A held findings row carries `id`, `held`, `held_code` and
//!   `blocker`; its `id` is a finding id, an attempt identity, or a
//!   `jobs/<entry>` or `attempts/<job>` path. Each poll verifies every
//!   retained finding's evidence digests, so its cost grows with the
//!   retained evidence bytes as well as the job count. Embedded records
//!   keep their own encoding, which omits some absent or false keys.
//! - `failure_groups`: verified findings grouped by failure `kind` and full
//!   failure `identity`, so findings of one failure under other seeds, runs
//!   or profiles read as one group; [`Group`] defines its keys.
//!
//! Readers keep an unknown branch for every label set. They treat an
//! unknown `state`, finish `class`, `binding`, finding `kind` or
//! `held_code` as held, and any other unknown label, such as a `purpose`,
//! `sim` `class`, `command`, `terminal`, `cause` or `ledger`, a triage
//! label or a disposition `decision`, as unattributed. A reader treats a
//! field this module names as unknown when a snapshot of the same format
//! omits it; a key inside an embedded record follows that record's own
//! encoding.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

use super::findings::{Known, Reads, Retained, attempt_number};
use super::{Error, name};
use crate::record::{
    Admission, Artifact, Attempt, Binding, BoundEvidence, Captured, Class, Configuration, Digest,
    FindingKind, Finished, Intent, Job, JobResult, Kernel, Pin, Purpose, Record, Started, Text,
    Verified,
};
use crate::store::{Dir, Name, View};

/// The snapshot format. A reader refuses a snapshot with another value and
/// ignores fields it does not read. A field added under one format keeps
/// the format, as does a new label in a label set; a removed field or a
/// changed field meaning takes a new format.
const FORMAT: u64 = 1;

/// Reads the snapshot of the state directory at `path`.
///
/// # Errors
///
/// - A refused or unmarked state directory, or a path that fails to
///   resolve.
/// - A state path containing invalid UTF-8 causes `Error::Rejected`.
/// - A host fault reading any record or directory.
/// - A failed open or listing of `jobs/`, `attempts/`, `probes/` or
///   `findings/`, a listing past the scan bound included. The same failure
///   on one job's attempt history, or on one entry beneath these
///   directories, is a held row.
/// - A listing the findings scan reads past the scan bound, such as
///   `calibrations/` or one calibration's replays. The scan applies the
///   bound independently to each listing.
/// - A failed free-space query, or a host fault reading the lock holders.
/// - A state directory that moved during the read, or a failed check of it.
pub fn status(path: &Path) -> Result<Snapshot, Error> {
    let view = View::unfenced(path)?;
    view.require_state_marker()?;
    let state = view
        .path()
        .to_str()
        .ok_or_else(|| Error::Rejected("the state path must be UTF-8".into()))?
        .to_owned();
    let observed_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    let config = match view.read_record::<Configuration>(view.root(), &name("config.json")) {
        Err(crate::record::Held::Unreadable(error)) if error.faulted() => {
            return Err(Error::Record(crate::record::Held::Unreadable(error)));
        }
        read => super::show::config(read),
    };
    let (free_bytes, free_inodes) = view.free_space()?;
    let early = view.lock_holders()?;
    let (probes, held_probes) = probes(&view)?;
    let mut variants = BTreeMap::new();
    let mut jobs = Vec::new();
    let mut entries = BTreeMap::new();
    let mut known = Known::default();
    let attempts = view.open_dir(view.root(), &name("attempts"))?;
    let mut job_listing = Vec::new();
    for shard in crate::campaign::sharded(&view, crate::layout::JOBS)? {
        let Some((shard, listing)) = placed_entries(&view, shard, &mut jobs, &mut known)? else {
            continue;
        };
        let (shard_entries, unknown) = job_entries(&listing);
        job_listing.extend(listing);
        let pass = Pass {
            view: &view,
            jobs: &shard.dir,
            attempts: attempts.as_ref(),
        };
        let ids: Vec<_> = shard_entries.iter().collect();
        let rows = pass.rows(&ids, &mut variants, &mut known)?;
        for ((id, _), row) in ids.iter().zip(rows) {
            jobs.push(((*id).clone(), row));
        }
        for entry in unknown {
            let row = encoded(&JobRow::Held(held_job(&entry, "unknown job entry")));
            jobs.push((entry, row));
        }
        entries.extend(shard_entries);
    }
    known.jobs = Some(job_listing);
    let mut histories = Vec::new();
    for shard in crate::campaign::sharded(&view, crate::layout::ATTEMPTS)? {
        let Some((_, listing)) = placed_entries(&view, shard, &mut jobs, &mut known)? else {
            continue;
        };
        for entry in &listing {
            if !entries.contains_key(entry.as_str()) && !admitted(&view, entry.as_str())? {
                let row = held_job(entry.as_str(), "attempt history without job record");
                jobs.push((entry.as_str().to_owned(), encoded(&JobRow::Held(row))));
            }
        }
        histories.extend(listing);
    }
    known.attempt_histories = Some(histories);
    jobs.sort_by(|(left, _), (right, _)| left.cmp(right));
    let mut listed = super::findings::listing(&view, known)?;
    let holders = match early {
        Ok(holders) if holders.iter().any(|holder| holder.exclusive) => Ok(holders),
        _ => view.lock_holders()?,
    };
    if !view.current().map_err(crate::store::Error::Io)? {
        return Err(Error::Held("state directory moved during status".into()));
    }
    for retained in &listed.retained {
        if let Some(code) = retained.triage_code {
            listed.findings[retained.row]["triage"]["held_code"] = code.into();
        }
    }
    let failure_groups = failure_groups(listed.retained.iter().map(Member::of));
    let lock = Lock::of(holders);
    Ok(Snapshot {
        config,
        failure_groups,
        findings: listed.findings,
        format: FORMAT,
        held_probes,
        jobs: jobs.into_iter().map(|(_, row)| row).collect(),
        lock,
        observed_ms,
        probes,
        release_blockers: listed.release_blockers,
        space: Space {
            free_bytes,
            free_inodes,
        },
        state,
        variants,
    })
}

/// The handles one job pass reads beneath.
#[derive(Clone, Copy)]
struct Pass<'a> {
    view: &'a View,
    jobs: &'a Dir,
    attempts: Option<&'a Dir>,
}

/// One job's encoded row, the variant it names and its reads for the
/// capture scan.
type Scanned = (String, Option<Variant>, Reads);

/// A variant key and the count map it names.
type Variant = (String, BTreeMap<Text, u64>);

impl Pass<'_> {
    /// The encoded rows of `ids` in order, read by [`super::threads::read_all`],
    /// with each row's variant joined to `variants` and its reads to
    /// `known`.
    ///
    /// # Errors
    ///
    /// The error of the lowest-index row that fails.
    fn rows(
        self,
        ids: &[(&String, &JobEntry)],
        variants: &mut BTreeMap<String, BTreeMap<Text, u64>>,
        known: &mut Known,
    ) -> Result<Vec<String>, Error> {
        let read = super::threads::read_all(ids, |(id, entry)| self.row(id, entry))?;
        known.settlements.reserve(read.len());
        known.histories.reserve(read.len());
        known.attempts.reserve(read.len());
        let mut rows = Vec::with_capacity(read.len());
        for (row, variant, reads) in read {
            if let Some((key, counts)) = variant {
                variants.entry(key).or_insert(counts);
            }
            known.join(reads);
            rows.push(row);
        }
        Ok(rows)
    }

    /// The row of job entry `id`.
    fn row(self, id: &str, entry: &JobEntry) -> Result<Scanned, Error> {
        let mut known = Reads::default();
        let row = match entry {
            JobEntry::Settlement => JobRow::Held(held_job(id, "settlement without job record")),
            JobEntry::Job => match super::show::checked(self.view, self.jobs, id) {
                Ok(admission) => {
                    known.settlements.push((format!("{id}.json"), Ok(None)));
                    let (row, variant) =
                        job(self.view, self.jobs, self.attempts, &admission, &mut known)?;
                    let row = encoded(&JobRow::Verified(Box::new(row)));
                    return Ok((row, Some(variant), known));
                }
                Err(error) if error.host_fault() => return Err(error),
                Err(error) => {
                    let row = JobRow::Held(HeldJob {
                        held: Held {
                            held: error.to_string(),
                            held_code: super::show::held_code(id, &error),
                        },
                        id: id.to_owned(),
                    });
                    if Digest::parse(id).is_some() {
                        known.settlements.push((format!("{id}.json"), Err(error)));
                    }
                    row
                }
            },
        };
        Ok((encoded(&row), None, known))
    }
}

/// Whether `jobs/<id>` now holds a verified admission. The `attempts/`
/// listing follows the `jobs/` listing, so a job admitted and dispatched
/// between the two has a history and no row.
fn admitted(view: &View, id: &str) -> Result<bool, Error> {
    let jobs = match crate::layout::jobs(view, id) {
        Err(error) if !error.faulted() => None,
        jobs => jobs?,
    };
    let Some(jobs) = jobs else {
        return Ok(false);
    };
    match super::show::checked(view, &jobs, id) {
        Ok(_) => Ok(true),
        Err(error) if error.host_fault() => Err(error),
        Err(_) => Ok(false),
    }
}

/// One snapshot of format [`FORMAT`]: the object the module documentation
/// describes, keys in byte order at every level. `jobs` holds each job
/// row's compact JSON, encoded by the thread that read the row.
///
/// Serde serializes fields in declaration order; keep each serialized
/// struct's declarations in byte order to preserve snapshot key ordering.
pub struct Snapshot {
    config: Value,
    failure_groups: Vec<Group>,
    findings: Vec<Value>,
    format: u64,
    held_probes: Vec<HeldEntry>,
    jobs: Vec<String>,
    lock: Lock,
    observed_ms: u64,
    probes: usize,
    release_blockers: Vec<String>,
    space: Space,
    state: String,
    variants: BTreeMap<String, BTreeMap<Text, u64>>,
}

impl Snapshot {
    /// Writes the snapshot's compact JSON to `out`, keys in byte order.
    ///
    /// # Errors
    ///
    /// The first failed write to `out`.
    pub fn write(&self, out: &mut impl Write) -> std::io::Result<()> {
        let Self {
            config,
            failure_groups,
            findings,
            format,
            held_probes,
            jobs,
            lock,
            observed_ms,
            probes,
            release_blockers,
            space,
            state,
            variants,
        } = self;
        out.write_all(b"{\"config\":")?;
        serde_json::to_writer(&mut *out, config)?;
        member(out, "failure_groups", failure_groups)?;
        member(out, "findings", findings)?;
        member(out, "format", format)?;
        member(out, "held_probes", held_probes)?;
        out.write_all(b",\"jobs\":[")?;
        for (index, row) in jobs.iter().enumerate() {
            if index > 0 {
                out.write_all(b",")?;
            }
            out.write_all(row.as_bytes())?;
        }
        out.write_all(b"]")?;
        member(out, "lock", lock)?;
        member(out, "observed_ms", observed_ms)?;
        member(out, "probes", probes)?;
        member(out, "release_blockers", release_blockers)?;
        member(out, "space", space)?;
        member(out, "state", state)?;
        member(out, "variants", variants)?;
        out.write_all(b"}")
    }
}

/// Writes `,"key":` and the compact JSON of `value` to `out`.
fn member(out: &mut impl Write, key: &str, value: &impl Serialize) -> std::io::Result<()> {
    out.write_all(b",\"")?;
    out.write_all(key.as_bytes())?;
    out.write_all(b"\":")?;
    serde_json::to_writer(&mut *out, value)?;
    Ok(())
}

/// The shard an iteration item names and its entries that belong there.
/// A root entry that is not a shard and an entry outside its job's shard
/// each become a held row of `jobs` and a held path of `known`.
fn placed_entries(
    view: &View,
    shard: Result<crate::layout::Shard, crate::store::Error>,
    jobs: &mut Vec<(String, String)>,
    known: &mut Known,
) -> Result<Option<(crate::layout::Shard, Vec<Name>)>, Error> {
    let mut hold = |path: String, reason: &str| {
        known.held.push((path.clone(), Error::Held(reason.into())));
        let row = encoded(&JobRow::Held(held_job(&path, reason)));
        jobs.push((path, row));
    };
    let shard = match shard {
        Err(crate::store::Error::Foreign(path)) => {
            hold(path, "root entry is not a shard");
            return Ok(None);
        }
        shard => shard?,
    };
    let (listing, misplaced): (Vec<_>, Vec<_>) = super::shard_entries(view, &shard)?
        .into_iter()
        .partition(|entry| super::findings::placed(&shard, entry.as_str()));
    for entry in misplaced {
        hold(
            format!("{}/{}", shard.path, entry.as_str()),
            "entry outside its job's shard",
        );
    }
    Ok(Some((shard, listing)))
}

fn encoded(row: &JobRow) -> String {
    serde_json::to_string(row).expect("a job row has only string map keys")
}

/// The `lock` member: the state directory's lock holders, or the reason
/// they could not be read.
#[derive(Serialize)]
pub(super) enum Lock {
    #[serde(rename = "holders")]
    Holders(Vec<LockHolder>),
    #[serde(rename = "unknown")]
    Unknown(String),
}

impl Lock {
    pub(super) fn of(holders: Result<Vec<crate::store::Holder>, String>) -> Self {
        match holders {
            Ok(holders) => Self::Holders(
                holders
                    .into_iter()
                    .map(|holder| LockHolder {
                        command: holder.command,
                        mode: if holder.exclusive {
                            "exclusive"
                        } else {
                            "shared"
                        },
                        pid: holder.pid,
                    })
                    .collect(),
            ),
            Err(reason) => Self::Unknown(reason),
        }
    }
}

#[derive(Serialize)]
pub(super) struct LockHolder {
    command: Option<String>,
    mode: &'static str,
    pid: Option<u32>,
}

#[derive(Serialize)]
struct Space {
    free_bytes: u64,
    free_inodes: u64,
}

/// A held row's reason and code.
#[derive(Serialize)]
struct Held {
    held: String,
    held_code: &'static str,
}

impl Held {
    /// The held row for `error`.
    ///
    /// # Errors
    ///
    /// Returns `error` itself when it is a host fault.
    fn of(error: Error) -> Result<Self, Error> {
        if error.host_fault() {
            return Err(error);
        }
        Ok(Self::by(&error))
    }

    /// Callers must propagate host faults before passing `error` to
    /// `Held::by`, as [`Held::of`] does.
    fn by(error: &Error) -> Self {
        Self {
            held: error.to_string(),
            held_code: error.held_code(),
        }
    }

    fn binding(reason: &str) -> Self {
        Self::by(&Error::Held(reason.into()))
    }
}

#[derive(Serialize)]
struct HeldEntry {
    entry: String,
    #[serde(flatten)]
    held: Held,
}

#[derive(Serialize)]
struct HeldJob {
    #[serde(flatten)]
    held: Held,
    id: String,
}

fn held_job(id: &str, reason: &str) -> HeldJob {
    HeldJob {
        id: id.to_owned(),
        held: Held::binding(reason),
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum Checked<T> {
    Verified(T),
    Held(Held),
}

#[derive(Serialize)]
#[serde(untagged)]
enum JobRow {
    Verified(Box<VerifiedJob>),
    Held(HeldJob),
}

#[derive(Serialize)]
struct VerifiedJob {
    attempts: Vec<AttemptEntry>,
    attempts_allowed: u64,
    attempts_held: Option<Held>,
    build: Text,
    campaign: Text,
    class: Option<Text>,
    executable: Text,
    id: String,
    pin: Option<Checked<Settlement>>,
    profile: Text,
    purpose: Purpose,
    result: Option<Checked<Settlement>>,
    run: u64,
    seed: u64,
    state: &'static str,
    variant: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum AttemptEntry {
    Verified(Box<AttemptRow>),
    Held(HeldEntry),
}

#[derive(Serialize)]
struct Settlement {
    attempt: u64,
    class: Class,
    exit: Option<u64>,
    signal: Option<u64>,
    watchdog: bool,
}

#[derive(Serialize)]
struct AttemptRow {
    attempt: String,
    captured: bool,
    finding: Option<Text>,
    finished: Option<Finish>,
    finished_ms: Option<u64>,
    intent_ms: Option<u64>,
    number: u64,
    sim: Option<Checked<Sim>>,
    started_ms: Option<u64>,
}

#[derive(Serialize)]
struct Finish {
    binding: Binding,
    class: Class,
    exit: Option<u64>,
    interruption: Option<u64>,
    kernel: Counters,
    residual_members: bool,
    signal: Option<u64>,
    watchdog: bool,
}

/// The CPU, memory event and PID event counters a monitor compares across
/// attempts. The cgroup is created per attempt, so each counter covers
/// that attempt alone.
#[derive(Serialize)]
struct Counters {
    cpu_nr_throttled: Option<u64>,
    cpu_throttled_usec: Option<u64>,
    cpu_usage_usec: Option<u64>,
    memory: BTreeMap<Text, u64>,
    pids: BTreeMap<Text, u64>,
}

#[derive(Serialize)]
struct Sim {
    cause: Option<Text>,
    class: Text,
    command: Text,
    decisions: Option<u64>,
    digest: Option<Digest>,
    failure_virtual_us: Option<u64>,
    identity: Option<Text>,
    ledger: Option<Text>,
    reason: Text,
    terminal: Option<Text>,
    unsuccessful: Option<Text>,
}

/// The number of `probes/` entries that open as directories, and a held row
/// for each other entry.
fn probes(view: &View) -> Result<(usize, Vec<HeldEntry>), Error> {
    let Some(root) = view.open_dir(view.root(), &name("probes"))? else {
        return Ok((0, Vec::new()));
    };
    let mut count = 0;
    let mut held = Vec::new();
    for entry in view
        .list(&root, crate::scan_bound())
        .map_err(|error| Error::listing("probes", error))?
    {
        match view.open_dir(&root, &entry) {
            Ok(Some(_)) => count += 1,
            Ok(None) => {}
            Err(error) => held.push(HeldEntry {
                entry: entry.as_str().to_owned(),
                held: Held::of(error.into())?,
            }),
        }
    }
    Ok((count, held))
}

/// What a job identity's `jobs/` entries hold: a job record or manifest, or
/// only settlement records.
enum JobEntry {
    Job,
    Settlement,
}

fn job_entries(listing: &[Name]) -> (BTreeMap<String, JobEntry>, Vec<String>) {
    let mut entries = BTreeMap::new();
    let mut unknown = Vec::new();
    for entry in listing {
        let value = entry.as_str();
        let job = value
            .strip_suffix(".manifest")
            .map(|id| (id, true))
            .or_else(|| value.strip_suffix(".bundle").map(|id| (id, true)))
            .or_else(|| value.strip_suffix(JobResult::SUFFIX).map(|id| (id, false)))
            .or_else(|| value.strip_suffix(".json").map(|id| (id, true)))
            .or_else(|| value.strip_suffix(Pin::SUFFIX).map(|id| (id, false)));
        match job {
            Some((id, true)) => {
                entries.insert(id.to_owned(), JobEntry::Job);
            }
            Some((id, false)) => {
                entries.entry(id.to_owned()).or_insert(JobEntry::Settlement);
            }
            None => unknown.push(value.to_owned()),
        }
    }
    (entries, unknown)
}

/// `job` builds a verified job's row from its frozen facts, attempts and
/// settlement records, and returns it with the job's variant key and count
/// map. Each settlement read, history listing and attempt capture state
/// joins `known`.
fn job(
    view: &View,
    jobs: &Dir,
    attempts: Option<&Dir>,
    admission: &Verified<Admission>,
    known: &mut Reads,
) -> Result<(VerifiedJob, Variant), Error> {
    let job = admission.record().job();
    let experiment = job.experiment();
    let counts = serde_json::to_vec(&experiment.counts).expect("a count map encodes");
    let variant = Digest::of(&counts).to_string()[..16].to_owned();
    let (mut rows, mut attempts_held) = match attempts {
        Some(root) => attempt_rows(view, root, job, known)?,
        None => (Vec::new(), None),
    };
    let result = settled::<JobResult>(view, jobs, job, JobResult::SUFFIX, |result| result, known)?;
    let pin = settled::<Pin>(view, jobs, job, Pin::SUFFIX, |pin| &pin.result, known)?;
    let settlement = result.is_some() || pin.is_some();
    // The history read precedes the settlement read, so a first attempt
    // dispatched and settled between them is listed once more from a fresh
    // `attempts/` handle.
    if rows.is_empty()
        && attempts_held.is_none()
        && settlement
        && let Some(root) = view.open_dir(view.root(), &name("attempts"))?
    {
        (rows, attempts_held) = attempt_rows(view, &root, job, known)?;
    }
    // Dispatch refuses a settlement record with no attempt history, and no
    // controller step removes a history, so the settlement's state is held.
    let unattempted = rows.is_empty() && attempts_held.is_none() && settlement;
    if unattempted {
        attempts_held = Some(Held::binding("settlement entry has no attempt history"));
    }
    let held_history =
        attempts_held.is_some() || rows.iter().any(|row| matches!(row, AttemptEntry::Held(_)));
    let state = match (&result, &pin, rows.last()) {
        _ if unattempted => "held",
        (Some(Checked::Verified(_)), _, _) => "settled",
        (Some(Checked::Held(_)), _, _) | (None, Some(Checked::Held(_)), _) => "held",
        (None, Some(Checked::Verified(_)), _) => "settling",
        (None, None, _) if held_history => "held",
        (None, None, None) => "queued",
        (None, None, Some(AttemptEntry::Verified(row))) if row.finished.is_none() => "running",
        (None, None, Some(_)) => "waiting",
    };
    let row = VerifiedJob {
        id: job.id().to_string(),
        profile: experiment.profile.clone(),
        campaign: experiment.campaign.clone(),
        run: experiment.run,
        seed: job.seed(),
        class: experiment.class.clone(),
        purpose: admission.record().purpose(),
        attempts_allowed: experiment.attempts,
        build: experiment.pins.build.clone(),
        executable: experiment.pins.executable.clone(),
        variant: variant.clone(),
        state,
        result,
        pin,
        attempts: rows,
        attempts_held,
    };
    Ok((row, (variant, experiment.counts.clone())))
}

/// The settlement row of `job`'s record with `suffix`: `None` when absent,
/// and a held row when the record fails the read rule or its result names
/// another job, manifest or attempt, or an attempt outside the frozen
/// limit. A present or held record's settled finish joins `known`.
fn settled<R: Record>(
    view: &View,
    jobs: &Dir,
    job: &Job,
    suffix: &str,
    result: impl Fn(&R) -> &JobResult,
    known: &mut Reads,
) -> Result<Option<Checked<Settlement>>, Error> {
    let id = job.id().to_string();
    let entry = format!("{id}{suffix}");
    let record = match view.read_record::<R>(jobs, &name(&entry)) {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(None),
        Err(error) => {
            let error = Error::Record(error);
            if error.host_fault() {
                return Err(error);
            }
            let held = Held::by(&error);
            known.settlements.push((entry, Err(error)));
            return Ok(Some(Checked::Held(held)));
        }
    };
    let result = result(record.record());
    let finish = super::findings::bound_finish(&id, result).map(Some);
    known.settlements.push((entry, finish));
    match settlement(job, result) {
        Ok(settled) => Ok(Some(Checked::Verified(settled))),
        Err(error) => Ok(Some(Checked::Held(Held::of(error)?))),
    }
}

fn settlement(job: &Job, result: &JobResult) -> Result<Settlement, Error> {
    super::findings::bound_finish(&job.id().to_string(), result)?;
    let finished = &result.finished;
    if result.manifest != job.manifest_sha256() || result.attempt > job.experiment().attempts {
        return Err(Error::Held("settlement binding differs".into()));
    }
    Ok(Settlement {
        attempt: result.attempt,
        class: finished.class,
        exit: finished.exit,
        signal: finished.signal,
        watchdog: finished.watchdog,
    })
}

/// The attempt rows of `job` in attempt number order, entries without a
/// canonical number last, and a held row for a history that cannot be
/// listed or whose numbers are not `1..=n`.
fn attempt_rows(
    view: &View,
    root: &Dir,
    job: &Job,
    known: &mut Reads,
) -> Result<(Vec<AttemptEntry>, Option<Held>), Error> {
    let id = job.id().to_string();
    let listed = view
        .open_dir(root, &crate::layout::shard(&id))
        .and_then(|shard| shard.map_or(Ok(None), |shard| view.open_dir(&shard, &name(&id))))
        .map_err(Error::from)
        .and_then(|directory| match directory {
            Some(directory) => {
                let entries = view.list(&directory, crate::scan_bound())?;
                Ok(Some((directory, entries)))
            }
            None => Ok(None),
        });
    let (directory, entries) = match listed {
        Ok(Some(listed)) => listed,
        Ok(None) => return Ok((Vec::new(), None)),
        Err(error) => return Ok((Vec::new(), Some(Held::of(error)?))),
    };
    known
        .histories
        .push((job.id().to_string(), entries.clone()));
    let mut numbered = Vec::new();
    let mut misnamed = Vec::new();
    for entry in entries {
        match attempt_number(&entry) {
            Ok(number) => numbered.push((number, entry)),
            Err(error) => misnamed.push(held_attempt(&entry, error)?),
        }
    }
    numbered.sort_unstable_by_key(|(number, _)| *number);
    let gaps = numbered
        .iter()
        .enumerate()
        .any(|(index, (number, _))| *number != index as u64 + 1);
    let mut rows = Vec::with_capacity(numbered.len() + misnamed.len());
    for (number, entry) in &numbered {
        rows.push(
            match attempt(view, &directory, entry, *number, job, known) {
                Ok(row) => AttemptEntry::Verified(Box::new(row)),
                Err(error) => held_attempt(entry, error)?,
            },
        );
    }
    rows.extend(misnamed);
    let history = gaps.then(|| Held::binding("attempt history has gaps or duplicates"));
    Ok((rows, history))
}

fn held_attempt(entry: &Name, error: Error) -> Result<AttemptEntry, Error> {
    Ok(AttemptEntry::Held(HeldEntry {
        entry: entry.as_str().to_owned(),
        held: Held::of(error)?,
    }))
}

/// The row of attempt directory `entry`, number `number`, whose records
/// must name attempt `{job}-{entry}`, the job's digest and manifest, and a
/// number within the frozen attempt limit. Once its finish and capture
/// marker are read, the attempt's capture state joins `known`.
fn attempt(
    view: &View,
    parent: &Dir,
    entry: &Name,
    number: u64,
    job: &Job,
    known: &mut Reads,
) -> Result<AttemptRow, Error> {
    if number > job.experiment().attempts {
        return Err(Error::Held(
            "attempt number outside the frozen limit".into(),
        ));
    }
    let attempt_id = format!("{}-{}", job.id(), entry.as_str());
    let directory = view
        .open_dir(parent, entry)?
        .ok_or_else(|| Error::Held("attempt directory vanished".into()))?;
    let mut record = view.read_record::<Attempt>(&directory, &name("attempt"))?;
    let mut intent = view.read_record::<Intent>(&directory, &name("intent"))?;
    let mut started = view.read_record::<Started>(&directory, &name("started"))?;
    let mut finished = view.read_record::<Finished>(&directory, &name("finished"))?;
    let captured = view.read_record::<Captured>(&directory, &name("captured"))?;
    // The controller publishes the attempt record, intent, started record,
    // finish and capture marker in that order and never removes one, so a
    // record read absent before a later record read present appeared
    // between the two reads; one re-read decides it.
    if captured.is_some() && finished.is_none() {
        finished = view.read_record::<Finished>(&directory, &name("finished"))?;
    }
    known.attempts.push((
        attempt_id.clone(),
        super::findings::capture_state(
            &attempt_id,
            finished.as_ref(),
            captured.as_ref(),
            job.experiment().target.is_some(),
        ),
    ));
    let pass = finished
        .as_ref()
        .is_some_and(|f| f.record().class == Class::Pass);
    if pass && started.is_none() {
        started = view.read_record::<Started>(&directory, &name("started"))?;
        if started.is_none() {
            return Err(Error::Held("pass lacks started witness".into()));
        }
    }
    if intent.is_none() && (started.is_some() || finished.is_some()) {
        intent = view.read_record::<Intent>(&directory, &name("intent"))?;
        if intent.is_none() {
            return Err(Error::Held("attempt lacks intent".into()));
        }
    }
    if record.is_none()
        && (intent.is_some() || started.is_some() || finished.is_some() || captured.is_some())
    {
        record = view.read_record::<Attempt>(&directory, &name("attempt"))?;
        if record.is_none() {
            return Err(Error::Held("attempt record missing".into()));
        }
    }
    let names = |text: &Text| text.as_str() == attempt_id;
    let named = record.as_ref().is_none_or(|r| names(&r.record().attempt))
        && intent.as_ref().is_none_or(|r| names(&r.record().attempt))
        && started.as_ref().is_none_or(|r| names(&r.record().attempt))
        && finished.as_ref().is_none_or(|r| {
            names(&r.record().attempt)
                && r.record()
                    .bound
                    .as_ref()
                    .is_none_or(|bound| names(&bound.attempt))
        })
        && captured.as_ref().is_none_or(|r| names(&r.record().attempt));
    if !named {
        return Err(Error::Held("attempt record names another attempt".into()));
    }
    if record.as_ref().is_some_and(|record| {
        let record = record.record();
        record.job != job.id().digest()
            || record.manifest != job.manifest_sha256()
            || record.number != number
    }) {
        return Err(Error::Held("attempt record binding differs".into()));
    }
    if let (Some(intent), Some(started)) = (&intent, &started)
        && !started.record().agrees_with(intent.record())
    {
        return Err(Error::Held("started record differs from its intent".into()));
    }
    if let Some(marker) = &captured {
        let Some(finished) = &finished else {
            return Err(Error::Held("capture marker without a finish".into()));
        };
        if !marker.record().matches(finished) {
            return Err(Error::Held("capture marker differs from the finish".into()));
        }
    }
    let sim = match &finished {
        Some(finish) => sim(view, &directory, &attempt_id, job, finish.record())?,
        None => None,
    };
    Ok(AttemptRow {
        number,
        intent_ms: written(intent.as_ref()),
        started_ms: written(started.as_ref()),
        finished_ms: written(finished.as_ref()),
        finished: finished.as_ref().map(|f| finish(f.record())),
        sim,
        finding: captured.as_ref().and_then(|c| c.record().finding.clone()),
        captured: captured.is_some(),
        attempt: attempt_id,
    })
}

fn written<R: Record>(record: Option<&Verified<R>>) -> Option<u64> {
    record.and_then(|record| record.read().modified_ms())
}

fn finish(finished: &Finished) -> Finish {
    Finish {
        class: finished.class,
        exit: finished.exit,
        signal: finished.signal,
        watchdog: finished.watchdog,
        interruption: finished.interruption,
        binding: finished.binding,
        residual_members: finished.residual_members,
        kernel: counters(&finished.kernel),
    }
}

fn counters(kernel: &Kernel) -> Counters {
    let cpu = |key: &str| {
        kernel
            .cpu
            .iter()
            .find(|(name, _)| name.as_str() == key)
            .map(|(_, value)| *value)
    };
    Counters {
        cpu_usage_usec: cpu("usage_usec"),
        cpu_throttled_usec: cpu("throttled_usec"),
        cpu_nr_throttled: cpu("nr_throttled"),
        memory: kernel.memory.clone(),
        pids: kernel.pids.clone(),
    }
}

fn sim(
    view: &View,
    attempt: &Dir,
    id: &str,
    job: &Job,
    finished: &Finished,
) -> Result<Option<Checked<Sim>>, Error> {
    let Some(bound) = &finished.bound else {
        if finished.binding == Binding::Matching {
            return Ok(Some(Checked::Held(Held::binding(
                "matching binding without bound evidence",
            ))));
        }
        return Ok(None);
    };
    let artifact = match bound_artifact(view, attempt, id, job, finished.binding, bound) {
        Ok(artifact) => artifact,
        Err(error) => return Ok(Some(Checked::Held(Held::of(error)?))),
    };
    let artifact = artifact.record();
    let summary = artifact.summary.as_ref();
    Ok(Some(Checked::Verified(Sim {
        class: artifact.class.clone(),
        command: artifact.command.clone(),
        reason: artifact.reason.clone(),
        terminal: summary.map(|s| s.terminal.clone()),
        cause: summary.and_then(|s| s.cause.clone()),
        identity: summary.and_then(|s| s.identity.clone()),
        digest: summary.map(|s| s.digest),
        decisions: summary.and_then(|s| s.decisions),
        ledger: summary.and_then(|s| s.ledger.clone()),
        unsuccessful: summary.and_then(|s| s.unsuccessful.clone()),
        failure_virtual_us: summary
            .and_then(|s| s.first_failure.as_ref())
            .and_then(|event| event.virtual_us),
    })))
}

fn bound_artifact(
    view: &View,
    attempt: &Dir,
    id: &str,
    job: &Job,
    binding: Binding,
    bound: &BoundEvidence,
) -> Result<Verified<Artifact>, Error> {
    if binding != Binding::Matching {
        return Err(Error::Held("bound evidence under another binding".into()));
    }
    let stored = view
        .read_record::<BoundEvidence>(attempt, &name("bound"))?
        .ok_or_else(|| Error::Held("finished lacks bound record".into()))?;
    if stored.record() != bound {
        return Err(Error::Held("stored binding differs".into()));
    }
    let artifact = super::findings::artifact_record(view, attempt, id, "bound")?;
    if Digest::of(artifact.read().bytes()) != bound.artifact {
        return Err(Error::Held("artifact differs from the bound digest".into()));
    }
    let record = artifact.record();
    if record.run_id.as_str() != id
        || record.command.as_str()
            != job
                .experiment()
                .target
                .as_ref()
                .map_or("run", |target| target.form.command())
        || record.manifest != Some(job.manifest_sha256())
        || record.archive.is_none()
        || record.archive != Digest::parse(job.experiment().pins.build.as_str())
        || record.bundle != bound.bundle
    {
        return Err(Error::Held("bound artifact binding differs".into()));
    }
    Ok(artifact)
}

/// One verified finding as [`failure_groups`] reads it.
pub(super) struct Member<'a> {
    pub(super) id: &'a str,
    pub(super) kind: FindingKind,
    pub(super) identity: Option<&'a Text>,
    pub(super) cause: Option<&'a Text>,
    pub(super) failure_virtual_us: Option<u64>,
    pub(super) profile: &'a Text,
    pub(super) run: u64,
    pub(super) resolved: bool,
}

impl<'a> Member<'a> {
    fn of(retained: &'a Retained) -> Self {
        let finding = &retained.finding;
        let summary = finding
            .artifact
            .as_ref()
            .and_then(|artifact| artifact.summary.as_ref());
        let experiment = finding.admission.job().experiment();
        Self {
            id: &retained.id,
            kind: finding.kind,
            identity: summary.and_then(|s| s.identity.as_ref()),
            cause: summary.and_then(|s| s.cause.as_ref()),
            failure_virtual_us: summary
                .and_then(|s| s.first_failure.as_ref())
                .and_then(|event| event.virtual_us),
            profile: &experiment.profile,
            run: experiment.run,
            resolved: retained.resolved,
        }
    }
}

/// One failure group: findings of one `kind` and full `identity`, or one
/// finding without an identity. `cause` and `failure_virtual_us` come from
/// the first finding in id order. `profiles` and `runs` list the members'
/// distinct values independently in first-seen order, so their positions
/// do not pair up. `unresolved` counts members whose latest disposition is
/// not `resolved`.
#[derive(Serialize)]
pub(super) struct Group {
    cause: Option<Text>,
    failure_virtual_us: Option<u64>,
    findings: Vec<String>,
    identity: Option<Text>,
    kind: FindingKind,
    profiles: Vec<Text>,
    runs: Vec<u64>,
    unresolved: u64,
}

/// Groups `members` by failure kind and full failure identity, in
/// first-seen order. A member without an identity forms its own group.
pub(super) fn failure_groups<'a>(members: impl IntoIterator<Item = Member<'a>>) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    let mut index = HashMap::new();
    let mut profiles = HashSet::new();
    let mut runs = HashSet::new();
    for member in members {
        let slot = match member.identity {
            Some(identity) => *index
                .entry((member.kind.name(), identity))
                .or_insert(groups.len()),
            None => groups.len(),
        };
        if slot == groups.len() {
            groups.push(Group {
                kind: member.kind,
                identity: member.identity.cloned(),
                cause: member.cause.cloned(),
                failure_virtual_us: member.failure_virtual_us,
                findings: Vec::new(),
                profiles: Vec::new(),
                runs: Vec::new(),
                unresolved: 0,
            });
        }
        let group = &mut groups[slot];
        group.findings.push(member.id.to_owned());
        if profiles.insert((slot, member.profile)) {
            group.profiles.push(member.profile.clone());
        }
        if runs.insert((slot, member.run)) {
            group.runs.push(member.run);
        }
        if !member.resolved {
            group.unresolved += 1;
        }
    }
    groups
}
