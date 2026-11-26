//! `sim-host run`: the runner that sweeps one root per stint and keeps its
//! roots stored. The main thread owns the state and the children; the
//! store pass, the read of the store's documents and the build fetch run on
//! their own threads beside the sweep, and a stint waits on the document
//! read for at most its own short bound. A root is marked deleting, under
//! its lock and with `state.json` saved, before any of its files is
//! removed.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::assignment::{Assignment, Document};
use crate::build::{self, Commit};
use crate::capture::Halt;
use crate::cgroup::Layout;
use crate::child::Child;
use crate::cli::Run;
use crate::health::{Health, Phase};
use crate::lines::Lines;
use crate::pass::{self, Output};
use crate::snapshot::{self, Observation};
use crate::state::{Confirmation, Retry, Root, State};
use crate::store::Bucket;
use crate::{cgroup, check, child, file, health, host, instance, lines, signal, state};

const POLL: Duration = Duration::from_millis(100);
const HEARTBEAT_MIN: Duration = Duration::from_secs(1);
const HEARTBEAT_MAX: Duration = Duration::from_secs(60);
const IDLE: Duration = Duration::from_secs(60);
const DOCS_WAIT: Duration = Duration::from_secs(15);
const FINAL_WAIT: Duration = Duration::from_secs(120);
/// The cap on [`record_period`].
const RECORD_MAX: Duration = Duration::from_secs(300);
const RECORD_RESERVE: Duration = Duration::from_secs(15);
const OBSERVE_WAIT: Duration = Duration::from_secs(60);
const FAILURES: u32 = 3;
const REPORT_MAX: u64 = 64 << 20;
const HELD_NAMES: usize = 8;

pub fn logs(state: &Path) -> PathBuf {
    state.join("logs")
}

/// The entries of `dir`. A step of the listing that fails fails the whole
/// listing, so a caller acts on every entry or on none.
fn entries(dir: &Path) -> std::io::Result<Vec<std::fs::DirEntry>> {
    std::fs::read_dir(dir)?.collect()
}

fn deadline(wait: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(wait)
        .expect("a wait of at most SECONDS_MAX seconds fits the monotonic clock")
}

const SWEEP_GRACE: Duration = Duration::from_secs(300);

fn sweep_limit(document: &Document) -> Duration {
    Duration::from_secs(document.stint.saturating_add(document.wall)).saturating_add(SWEEP_GRACE)
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Usage {
    Absent,
    Value(u64),
    Unknown,
}

fn usage(group: &Path) -> Usage {
    match cgroup::usage_usec(group) {
        Ok(None) => Usage::Absent,
        Ok(Some(value)) => Usage::Value(value),
        Err(_) => Usage::Unknown,
    }
}

fn used(before: Usage, after: Usage) -> Option<u64> {
    match (before, after) {
        (Usage::Absent, Usage::Absent) => Some(0),
        (Usage::Absent, Usage::Value(after)) => Some(after),
        (Usage::Value(before), Usage::Value(after)) if after >= before => Some(after - before),
        _ => None,
    }
}

fn stop_deadlines(start: Instant) -> (Instant, Instant) {
    let until = start + FINAL_WAIT;
    (until - RECORD_RESERVE, until)
}

fn record_period(stint: Duration) -> Duration {
    (stint / 2).min(RECORD_MAX).saturating_sub(POLL)
}

/// The milliseconds a root with `retry` still waits at `now_ms` on the
/// boot `boot`, with the record to save in its place when it changes. A
/// retry of another boot, or one that waits longer than `stint_ms`, waits a
/// full `stint_ms` from `now_ms`, since the boot clock restarts at each
/// boot.
pub fn retry_wait(
    retry: Option<&Retry>,
    boot: &str,
    now_ms: u64,
    stint_ms: u64,
) -> (u64, Option<Retry>) {
    let Some(retry) = retry else {
        return (0, None);
    };
    let full = || {
        let rewrite = Retry {
            boot: boot.to_owned(),
            until_ms: now_ms.saturating_add(stint_ms),
        };
        (stint_ms, Some(rewrite))
    };
    if retry.boot != boot {
        return full();
    }
    match retry.until_ms.checked_sub(now_ms) {
        None | Some(0) => (0, None),
        Some(remaining) if remaining > stint_ms => full(),
        Some(remaining) => (remaining, None),
    }
}

#[derive(Debug, Default, Deserialize)]
struct Report {
    dispatch: Option<String>,
    refusals: Option<Vec<String>>,
    rejections: Option<Vec<String>>,
}

/// The last of the JSON reports in the file at `path`, read whole at most
/// [`REPORT_MAX`] bytes, or `None` when the file is absent, longer, empty,
/// or holds a document that does not parse.
fn report(path: &Path) -> Option<Report> {
    let bytes = file::read(path, REPORT_MAX).ok()??;
    let mut last = None;
    let values = serde_json::Deserializer::from_slice(&bytes).into_iter::<Report>();
    for value in values {
        last = Some(value.ok()?);
    }
    last
}

/// The text in `campaign`'s standard error when its report leaves refusals
/// out of the sample it prints.
pub const OMITTED_REFUSALS: &str = "omitted refusals:";

/// The key of `campaign confirm`'s report whose value names how its
/// dispatch ended.
pub const DISPATCH: &str = "dispatch";
/// The dispatch value of a confirm that a signal ended before its queue
/// settled; it settles nothing.
pub const INTERRUPTED: &str = "interrupted";
/// The dispatch value of a confirm that left no admitted job.
pub const QUEUE_EMPTY: &str = "queue_empty";

/// Whether `refusal` has the prefix and suffix of `campaign confirm`'s
/// backlog hold. It reads the text's shape only.
pub fn is_backlog_hold(refusal: &str) -> bool {
    refusal.starts_with("backlog holds ")
        && refusal.ends_with("; dispose findings or raise backlog")
}

fn backlog_only(report: Option<&Report>, stderr: Option<&str>) -> bool {
    let (
        Some(Report {
            refusals: Some(refusals),
            rejections: Some(rejections),
            ..
        }),
        Some(stderr),
    ) = (report, stderr)
    else {
        return false;
    };
    !refusals.is_empty()
        && rejections.is_empty()
        && !stderr.contains(OMITTED_REFUSALS)
        && refusals.iter().all(|refusal| is_backlog_hold(refusal))
}

struct Confirming {
    child: Child,
    campaign: String,
}

struct Sample {
    stint: u64,
    cpu: u64,
    capacity: u64,
}

struct Fetching {
    commit: Commit,
    handle: JoinHandle<Result<(), String>>,
}

enum RootChoice {
    Ready(String),
    Blocked(String),
}

pub struct Runner {
    options: Run,
    bucket: Bucket,
    instance: String,
    layout: Layout,
    state: State,
    latest: Option<(Document, Commit)>,
    fetched: Option<Commit>,
    assignment: Option<Assignment>,
    assignment_error: Option<String>,
    upload_error: Option<String>,
    fetch_error: Option<String>,
    cleanup_error: Option<String>,
    pass: Option<JoinHandle<Output>>,
    docs: Option<JoinHandle<Result<(Document, Commit), String>>>,
    fetch: Option<Fetching>,
    fetch_after: Option<Instant>,
    adopted: bool,
    observed: Option<Result<Observation, String>>,
    confirmed_since: BTreeSet<String>,
    confirm: Option<Confirming>,
    confirm_after: BTreeMap<String, Instant>,
    lines: BTreeMap<String, Lines>,
    earlier_cursor: Option<String>,
    last_confirmed: Option<String>,
    confirm_exit_root: Option<String>,
    exits: BTreeMap<String, i32>,
    phase: Phase,
    reason: Option<String>,
    sample: Option<Sample>,
    /// When the running sweep passes [`sweep_limit`]; `None` between sweeps.
    sweep_due: Option<Instant>,
    health_written: Option<Instant>,
    record: Option<JoinHandle<Result<(), String>>>,
    record_started: Option<(Instant, Option<u64>)>,
    record_stored: Option<Option<u64>>,
    record_error: Option<String>,
}

pub fn run(options: Run) -> u8 {
    if let Err(error) = file::private_dir(&options.state) {
        eprintln!("sim-host run: {error}");
        return 2;
    }
    let lock_path = options.state.join("runner.lock");
    let _lock = match file::lock(&lock_path) {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            eprintln!(
                "sim-host run: another runner holds {}",
                options.state.display()
            );
            return 2;
        }
        Err(error) => {
            eprintln!("sim-host run: {}: {error}", lock_path.display());
            return 2;
        }
    };
    let state_dir = options.state.clone();
    match start(options) {
        Ok(mut runner) => runner.serve(),
        Err(error) => {
            eprintln!("sim-host run: {error}");
            let health = Health {
                format: Some(1),
                written: Some(host::now_s()),
                phase: Some(Phase::Blocked.name().to_owned()),
                reason: Some(error),
                ..Health::default()
            };
            if let Err(error) = health::save(&state_dir, &health) {
                eprintln!("sim-host run: {error}");
            }
            2
        }
    }
}

fn start(options: Run) -> Result<Runner, String> {
    for dir in [
        state::roots(&options.state),
        logs(&options.state),
        build::builds(&options.state),
        state::assignments(&options.state),
        snapshot::uploads(&options.state),
    ] {
        file::private_dir(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    }
    let instance = instance::instance_id()
        .map_err(|error| format!("{error}; the runner needs the EC2 instance id"))?;
    let state = state::load(&options.state)?;
    let unit = options
        .host
        .cgroup
        .clone()
        .map_or_else(cgroup::own, Ok)
        .map_err(|error| error.to_string())?;
    cgroup::real(&unit).map_err(|error| format!("the cgroup {}: {error}", unit.display()))?;
    let layout = cgroup::delegate(&unit)
        .map_err(|error| format!("the cgroup layout under {}: {error}", unit.display()))?;
    signal::install().map_err(|error| format!("signal handlers: {error}"))?;
    Ok(Runner {
        bucket: Bucket::new(&options.host.bucket),
        options,
        instance,
        layout,
        state,
        latest: None,
        fetched: None,
        assignment: None,
        assignment_error: None,
        upload_error: None,
        fetch_error: None,
        cleanup_error: None,
        pass: None,
        docs: None,
        fetch: None,
        fetch_after: None,
        adopted: false,
        observed: None,
        confirmed_since: BTreeSet::new(),
        confirm: None,
        confirm_after: BTreeMap::new(),
        lines: BTreeMap::new(),
        earlier_cursor: None,
        last_confirmed: None,
        confirm_exit_root: None,
        exits: BTreeMap::new(),
        phase: Phase::Starting,
        reason: None,
        sample: None,
        sweep_due: None,
        health_written: None,
        record: None,
        record_started: None,
        record_stored: None,
        record_error: None,
    })
}

impl Runner {
    fn serve(&mut self) -> u8 {
        let mut outcome = self.restore_assignment();
        let after = deadline(self.stint_length());
        for (campaign, root) in &self.state.roots {
            if root.instance == self.instance
                && (root.confirmation != Confirmation::Idle || root.pending)
            {
                self.confirm_after.insert(campaign.clone(), after);
            }
        }
        if outcome.is_ok() {
            outcome = self.finish_deletions();
        }
        self.write_health();
        self.start_record();
        while outcome.is_ok() && !signal::stopping() {
            outcome = self.stint();
        }
        let code = match outcome {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("sim-host run: {error}");
                self.reason = Some(error);
                1
            }
        };
        signal::request_stop();
        self.stop();
        code
    }

    /// Loads the recorded assignment copy, then reads the store's documents
    /// for at most [`DOCS_WAIT`] and composes the copy, so
    /// [`Runner::stint_length`] is the stint of the assignment in force when
    /// `serve` sets the restart waits. No poll runs during that read, so no
    /// `confirm` starts before those waits are set.
    fn restore_assignment(&mut self) -> Result<(), String> {
        if let Err(error) = self.load_copy() {
            self.assignment_error = Some(error);
        }
        self.start_docs();
        let until = deadline(DOCS_WAIT);
        while self.docs_pending(until) {
            std::thread::sleep(POLL);
        }
        self.poll_docs()?;
        self.compose()
    }

    fn stint_length(&self) -> Duration {
        self.stint_seconds().map_or(IDLE, Duration::from_secs)
    }

    fn stint_seconds(&self) -> Option<u64> {
        self.assignment
            .as_ref()
            .map(|assignment| assignment.document.stint)
    }

    fn current(&self) -> Option<&Root> {
        self.state
            .current
            .as_ref()
            .and_then(|campaign| self.state.roots.get(campaign))
            .filter(|root| root.instance == self.instance)
    }

    fn root(&self, campaign: &str) -> Result<&Root, String> {
        self.state
            .roots
            .get(campaign)
            .ok_or_else(|| format!("root {campaign} is not recorded"))
    }

    fn root_mut(&mut self, campaign: &str) -> Result<&mut Root, String> {
        self.state
            .roots
            .get_mut(campaign)
            .ok_or_else(|| format!("root {campaign} is not recorded"))
    }

    fn save(&self) -> Result<(), String> {
        state::save(&self.options.state, &self.state)
    }

    fn load_copy(&mut self) -> Result<(), String> {
        let Some(digest) = self.state.assignment.clone() else {
            return Ok(());
        };
        let path = state::assignment_path(&self.options.state, &digest);
        let bytes = file::read(&path, crate::assignment::COPY_BOUND)
            .map_err(|error| format!("{}: {error}", path.display()))?
            .ok_or_else(|| format!("{} is missing", path.display()))?;
        if file::sha256(&bytes) != digest {
            return Err(format!(
                "{} differs from its recorded digest",
                path.display()
            ));
        }
        self.assignment = Some(Assignment::parse(&bytes)?);
        Ok(())
    }

    fn on_disk(&self, commit: &Commit) -> bool {
        build::installed(&self.options.state, commit)
    }

    /// Whether a fetch of `commit`'s build is running. Its tree can be at
    /// the final path before the fetch syncs `builds/`, and a failed sync
    /// removes it again, so the build is used only after the fetch returns.
    fn fetching(&self, commit: &Commit) -> bool {
        self.fetching_build(&commit.build)
    }

    fn fetching_build(&self, build: &str) -> bool {
        self.fetch
            .as_ref()
            .is_some_and(|fetching| fetching.commit.build == build)
    }

    fn compose(&mut self) -> Result<(), String> {
        let Some((document, latest)) = self.latest.clone() else {
            return Ok(());
        };
        let commit = if !self.fetching(&latest) && self.on_disk(&latest) {
            self.fetched = None;
            latest
        } else if let Some(fetched) = self.fetched.clone()
            && !self.fetching(&fetched)
            && self.on_disk(&fetched)
        {
            fetched
        } else if let Some(previous) = &self.assignment {
            previous.commit.clone()
        } else {
            return Ok(());
        };
        let assignment = Assignment { document, commit };
        let bytes = serde_json::to_vec(&assignment).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > crate::assignment::COPY_BOUND {
            self.assignment_error = Some(format!(
                "the stored copy would hold {} bytes, past {}",
                bytes.len(),
                crate::assignment::COPY_BOUND
            ));
            return Ok(());
        }
        let digest = file::sha256(&bytes);
        let recorded = self.state.assignment.as_deref() == Some(digest.as_str());
        let copy = state::assignment_path(&self.options.state, &digest);
        let stored = file::read(&copy, crate::assignment::COPY_BOUND)
            .ok()
            .flatten();
        if (!recorded || stored.as_deref() != Some(bytes.as_slice()))
            && let Err(error) = file::replace(&copy, &bytes)
        {
            self.assignment_error = Some(format!("{}: {error}", copy.display()));
            return Ok(());
        }
        if !recorded {
            self.state.assignment = Some(digest);
            self.save()?;
        }
        self.assignment = Some(assignment);
        Ok(())
    }

    fn assigned(&self) -> Option<String> {
        self.latest
            .as_ref()
            .map(|(_, commit)| commit.build.clone())
            .or_else(|| {
                self.assignment
                    .as_ref()
                    .map(|assignment| assignment.build().to_owned())
            })
    }

    fn start_pass(&mut self) {
        if self.pass.is_some() || signal::stopping() {
            return;
        }
        let mut input = pass::Input {
            bucket: self.bucket.clone(),
            state: self.options.state.clone(),
            instance: self.instance.clone(),
            roots: self.state.roots.clone(),
            current: self.state.current.clone(),
            assigned: self.assigned(),
            confirming: self
                .confirm
                .as_ref()
                .map(|confirming| confirming.campaign.clone()),
            stint_seconds: self.stint_seconds(),
            observed: self.observed.take(),
            at_rest: false,
        };
        self.confirmed_since.clear();
        self.pass = Some(std::thread::spawn(move || pass::pass(&mut input)));
    }

    fn record_uploads(&mut self, output: &Output) {
        self.upload_error = (!output.errors.is_empty()).then(|| output.errors.join("; "));
    }

    fn poll_pass(&mut self) -> Result<(), String> {
        if !self.pass.as_ref().is_some_and(JoinHandle::is_finished) {
            return Ok(());
        }
        let output = self
            .pass
            .take()
            .expect("a finished pass")
            .join()
            .map_err(|_| "the store pass panicked".to_owned())?;
        // A stop halts the pass's store calls, and the final upload records
        // its own errors.
        if !signal::stopping() {
            self.record_uploads(&output);
        }
        let assigned = self.assigned();
        for (campaign, stamp) in output.deletable {
            let confirming = self
                .confirm
                .as_ref()
                .is_some_and(|confirming| confirming.campaign == campaign);
            let retirable = self.state.current.as_deref() != Some(campaign.as_str())
                && !confirming
                && !self.confirmed_since.contains(&campaign);
            let dir = state::roots(&self.options.state).join(&campaign);
            let Some(root) = self.state.roots.get(&campaign) else {
                continue;
            };
            if !(retirable
                && assigned
                    .as_deref()
                    .is_some_and(|assigned| assigned != root.build)
                && root.confirmation == Confirmation::Idle
                && !root.pending)
            {
                continue;
            }
            // The root's lock excludes `campaign sweep`, and the lock of
            // `confirm/state` excludes `campaign` commands that write
            // findings. Both are held from the stamp's second reading
            // through the mark and the rename of the root out of place.
            // `campaign confirm` writes `confirm/confirmed` after it drops
            // the lock of `confirm/state`, so the checks above keep a
            // confirm off the root: `confirming`, `pending` and
            // `confirmed_since` skip a root whose confirm is running or
            // started since the pass began. Each confirm starts after
            // `poll_pass` returns, when both locks are released.
            let Ok(held) = file::lock_dir(&dir) else {
                continue;
            };
            let Ok(state_held) = file::lock_dir(&dir.join("confirm/state")) else {
                continue;
            };
            if snapshot::stamp(&dir) == stamp {
                self.root_mut(&campaign)?.deleting = true;
                self.save()?;
                // A failed rename leaves the marked root in place, and
                // `finish_deletions` below discards it and names the error.
                let _ = file::detach(&dir);
            }
            drop(state_held);
            drop(held);
        }
        self.finish_deletions()?;
        self.write_health();
        Ok(())
    }

    fn start_docs(&mut self) {
        if self.docs.is_none() && !signal::stopping() {
            let bucket = self.bucket.clone();
            let scratch = self.options.state.join("store");
            self.docs = Some(std::thread::spawn(move || pass::docs(&bucket, &scratch)));
        }
    }

    /// Whether a read of the store's documents is still running before
    /// `until` with no stop requested.
    fn docs_pending(&self, until: Instant) -> bool {
        !signal::stopping()
            && Instant::now() < until
            && self.docs.as_ref().is_some_and(|docs| !docs.is_finished())
    }

    fn read_docs(&mut self) -> Result<(), String> {
        self.start_docs();
        let until = deadline(DOCS_WAIT);
        while self.docs_pending(until) {
            self.tick()?;
            std::thread::sleep(POLL);
        }
        self.poll_docs()
    }

    fn poll_docs(&mut self) -> Result<(), String> {
        if !self.docs.as_ref().is_some_and(JoinHandle::is_finished) {
            return Ok(());
        }
        let read = self
            .docs
            .take()
            .expect("a finished read")
            .join()
            .map_err(|_| "the assignment read panicked".to_owned())?;
        match read {
            Ok(docs) => {
                if self.latest.as_ref().map(|(_, commit)| commit) != Some(&docs.1) {
                    self.fetch_after = None;
                }
                self.latest = Some(docs);
                self.assignment_error = None;
            }
            Err(error) if signal::stopping() => drop(error),
            Err(error) => self.assignment_error = Some(error),
        }
        Ok(())
    }

    fn start_fetch(&mut self) {
        if self.fetch.is_some()
            || signal::stopping()
            || self.fetch_after.is_some_and(|after| Instant::now() < after)
        {
            return;
        }
        let Some((_, commit)) = self.latest.clone() else {
            return;
        };
        if self.on_disk(&commit) {
            self.fetch_error = None;
            return;
        }
        let bucket = self.bucket.clone();
        let state = self.options.state.clone();
        let reserve = self.options.disk_reserve;
        let fetched = commit.clone();
        let handle = std::thread::spawn(move || build::fetch(&bucket, &state, &fetched, reserve));
        self.fetch = Some(Fetching { commit, handle });
    }

    fn poll_fetch(&mut self) -> Result<(), String> {
        if !self
            .fetch
            .as_ref()
            .is_some_and(|fetching| fetching.handle.is_finished())
        {
            return Ok(());
        }
        let fetching = self.fetch.take().expect("a finished fetch");
        let fetched = fetching
            .handle
            .join()
            .map_err(|_| "the build fetch panicked".to_owned())?;
        match fetched {
            Ok(()) => {
                self.fetched = Some(fetching.commit);
                self.fetch_error = None;
                self.adopted = true;
            }
            Err(error) if signal::stopping() => drop(error),
            Err(error) => {
                self.fetch_error = Some(error);
                let wait = self
                    .latest
                    .as_ref()
                    .map_or(self.stint_length(), |(document, _)| {
                        Duration::from_secs(document.stint)
                    });
                self.fetch_after = Some(deadline(wait));
            }
        }
        self.write_health();
        Ok(())
    }

    fn finish_deletions(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        let deleting: Vec<String> = self
            .state
            .roots
            .iter()
            .filter(|(_, root)| root.deleting && root.instance == self.instance)
            .map(|(campaign, _)| campaign.clone())
            .collect();
        for campaign in deleting {
            let dir = state::roots(&self.options.state).join(&campaign);
            let held = match file::lock_dir(&dir) {
                Ok(held) => held,
                Err(error) if matches!(error.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
                    None
                }
                Err(error) => {
                    errors.push(format!("{}: {error}", dir.display()));
                    continue;
                }
            };
            let mut removed = true;
            for dir in [
                dir.clone(),
                snapshot::uploads(&self.options.state).join(&campaign),
            ] {
                if let Err(error) = file::discard(&dir) {
                    errors.push(format!("{}: {error}", dir.display()));
                    removed = false;
                }
            }
            drop(held);
            let nonce = self.state.roots[&campaign].nonce.clone();
            let group = self.layout.confirm_root(&nonce);
            for group in [group.join("controller"), group] {
                match std::fs::remove_dir(&group) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        errors.push(format!("{}: {error}", group.display()));
                        removed = false;
                    }
                }
            }
            if removed {
                self.state.roots.remove(&campaign);
                self.lines.remove(&campaign);
                self.confirm_after.remove(&campaign);
                self.save()?;
            }
        }
        if let Some(digest) = &self.state.assignment {
            let kept = format!("{digest}.json");
            let copies = state::assignments(&self.options.state);
            let listed = entries(&copies).unwrap_or_else(|error| {
                errors.push(format!("{}: {error}", copies.display()));
                Vec::new()
            });
            for entry in listed {
                let name = entry.file_name().to_string_lossy().into_owned();
                let copy = name
                    .strip_prefix('.')
                    .and_then(|name| name.strip_suffix(".json.staged"))
                    .or_else(|| name.strip_suffix(".json"));
                // Every copy is a regular file. `remove_file` fails on a
                // directory under a copy's name, which stays and is named
                // under `cleanup_error`, and unlinks any other entry itself.
                if name != kept
                    && copy.is_some_and(file::is_sha256)
                    && let Err(error) = std::fs::remove_file(entry.path())
                {
                    errors.push(format!("{}: {error}", entry.path().display()));
                }
            }
        }
        let builds = build::builds(&self.options.state);
        if self.latest.is_some() {
            let mut kept: BTreeSet<String> = self
                .state
                .roots
                .values()
                .map(|root| root.build.clone())
                .collect();
            kept.extend(self.assigned());
            kept.extend(
                self.assignment
                    .as_ref()
                    .map(|assignment| assignment.build().to_owned()),
            );
            kept.extend(self.fetched.as_ref().map(|commit| commit.build.clone()));
            let fetching = self
                .fetch
                .as_ref()
                .map(|fetching| fetching.commit.build.clone());
            kept.extend(fetching.clone());
            let listed = entries(&builds).unwrap_or_else(|error| {
                errors.push(format!("{}: {error}", builds.display()));
                Vec::new()
            });
            for entry in listed {
                let name = entry.file_name().to_string_lossy().into_owned();
                let staging = name.strip_prefix(".fetch-");
                let stale = match staging {
                    Some(build) => fetching.as_deref() != Some(build),
                    None => {
                        file::is_sha256(&name)
                            && entry.file_type().is_ok_and(|kind| kind.is_dir())
                            && !kept.contains(&name)
                    }
                };
                if !stale {
                    continue;
                }
                let removed = if staging.is_some() {
                    file::remove_entry(&entry.path())
                } else {
                    file::discard(&entry.path())
                };
                if let Err(error) = removed {
                    errors.push(format!("{}: {error}", entry.path().display()));
                }
            }
        }
        for dir in [
            builds,
            state::roots(&self.options.state),
            snapshot::uploads(&self.options.state),
        ] {
            if let Err(error) = file::sweep_trash(&dir) {
                errors.push(format!("{}: {error}", dir.display()));
            }
        }
        self.cleanup_error = (!errors.is_empty()).then(|| errors.join("; "));
        Ok(())
    }

    fn root_for(&mut self, assignment: &Assignment) -> Result<RootChoice, String> {
        let slots = self.options.host.confirm_slots;
        let mut carried = None;
        if let Some(root) = self.current()
            && assignment.binds(root)
            && root.confirm_slots == slots
        {
            if root.failures < FAILURES {
                return Ok(RootChoice::Ready(root.campaign()));
            }
            carried = root.retry.clone();
        }
        let nonce = host::random_hex(16).map_err(|error| format!("a root nonce: {error}"))?;
        let root = Root {
            name: assignment.document.name.clone(),
            instance: self.instance.clone(),
            nonce,
            build: assignment.build().to_owned(),
            counts: assignment.document.counts.clone(),
            confirm_slots: slots,
            stints: 0,
            failures: 0,
            cpu_usec: 0,
            capacity_usec: 0,
            alarm: false,
            confirmation: Confirmation::Idle,
            pending: false,
            retry: carried,
            deleting: false,
        };
        let campaign = root.campaign();
        let previous = self.state.current.replace(campaign.clone());
        self.state.roots.insert(campaign.clone(), root);
        if let Err(error) = self.save() {
            self.state.roots.remove(&campaign);
            self.state.current = previous;
            return Ok(RootChoice::Blocked(format!(
                "a new root is not recorded: {error}"
            )));
        }
        self.sample = None;
        self.observed = None;
        Ok(RootChoice::Ready(campaign))
    }

    fn observe_current(&mut self) {
        if self.observed.is_some() {
            return;
        }
        let Some(root) = self.current().cloned() else {
            return;
        };
        if root.instance != self.instance || self.fetching_build(&root.build) {
            return;
        }
        let sweep = state::roots(&self.options.state)
            .join(root.campaign())
            .join("sweep.json");
        self.observed = match file::exists(&sweep) {
            Ok(true) => Some(snapshot::observe(
                &self.options.state,
                &root,
                Halt::At(deadline(OBSERVE_WAIT)),
            )),
            Ok(false) => None,
            Err(error) => Some(Err(format!("{}: {error}", sweep.display()))),
        };
    }

    fn stint(&mut self) -> Result<(), String> {
        self.read_docs()?;
        if signal::stopping() {
            return Ok(());
        }
        self.poll_fetch()?;
        self.compose()?;
        self.observe_current();
        self.start_pass();
        self.start_fetch();
        let Some(assignment) = self.assignment.clone() else {
            let reason = self
                .fetch_error
                .clone()
                .or_else(|| self.assignment_error.clone())
                .unwrap_or_else(|| "waiting for the assignment and its build".into());
            self.adopted = false;
            return self.pause(Phase::Blocked, reason, IDLE);
        };
        let wait = Duration::from_secs(assignment.document.stint);
        if self.fetching(&assignment.commit) {
            let reason = format!("builds/{} is being fetched", assignment.build());
            return self.pause(Phase::Blocked, reason, wait);
        }
        if !self.on_disk(&assignment.commit) {
            let reason = build::verify_recorded(&self.options.state, assignment.build())
                .err()
                .unwrap_or_else(|| {
                    format!(
                        "builds/{}/record.json names another campaign binary",
                        assignment.build()
                    )
                });
            return self.pause(Phase::Blocked, reason, wait);
        }
        let campaign = match self.root_for(&assignment)? {
            RootChoice::Ready(campaign) => campaign,
            RootChoice::Blocked(reason) => return self.pause(Phase::Blocked, reason, wait),
        };
        self.reap_confirm()?;
        let stint_ms = assignment.document.stint.saturating_mul(1000);
        let (remaining, rewrite) = retry_wait(
            self.root(&campaign)?.retry.as_ref(),
            &host::boot_id(),
            host::boot_ms(),
            stint_ms,
        );
        if remaining > 0 {
            if let Some(retry) = rewrite {
                self.root_mut(&campaign)?.retry = Some(retry);
                self.save()?;
            }
            let reason = format!(
                "a failed sweep of the root starts again in {} s",
                remaining.div_ceil(1000)
            );
            return self.pause(Phase::Waiting, reason, Duration::from_millis(remaining));
        }
        if let Confirmation::Held(reason) = &self.root(&campaign)?.confirmation {
            let reason = format!("confirm is held: {reason}");
            return self.pause(Phase::Held, reason, wait);
        }
        let roots = state::roots(&self.options.state);
        match file::free_bytes(&roots) {
            Ok(free) if free < self.options.disk_reserve => {
                let reason = format!(
                    "{free} bytes are free under {}, below the reserve of {}",
                    roots.display(),
                    self.options.disk_reserve
                );
                return self.pause(Phase::Full, reason, wait);
            }
            Ok(_) => {}
            Err(error) => {
                let reason = format!("{}: {error}", roots.display());
                return self.pause(Phase::Blocked, reason, wait);
            }
        }
        if self.root(&campaign)?.stints == u64::MAX {
            let reason = format!("root {campaign} has no stint number left");
            return self.pause(Phase::Blocked, reason, wait);
        }
        let host = &self.options.host;
        let Some(workers) =
            check::workers(host::online_cpus(), host.confirm_slots, host.system_cores)
        else {
            let reason = format!(
                "the partition leaves no worker count from 1 to {}",
                check::WORKERS_MAX
            );
            return self.pause(Phase::Blocked, reason, wait);
        };
        let demand = check::demand(
            workers,
            assignment.document.memory,
            host.confirm_slots,
            self.options.system_memory,
        );
        match host::memory_bytes() {
            Ok(memory) if demand <= memory => {}
            Ok(memory) => {
                let reason = format!(
                    "workers, confirmation and the system reserve need {demand} bytes of \
                     memory and the host has {memory}"
                );
                return self.pause(Phase::Blocked, reason, wait);
            }
            Err(error) => {
                let reason = format!("the host's memory: {error}");
                return self.pause(Phase::Blocked, reason, wait);
            }
        }
        if signal::stopping() {
            return Ok(());
        }
        self.sweep(&assignment, &campaign, workers)
    }

    fn sweep_args(&self, assignment: &Assignment, campaign: &str, workers: u64) -> Vec<String> {
        let root = state::roots(&self.options.state).join(campaign);
        let archive = build::archive(&self.options.state, assignment.build());
        let document = &assignment.document;
        let mut args: Vec<String> = [
            "sweep",
            "--root",
            &root.to_string_lossy(),
            "--archive",
            &archive.to_string_lossy(),
            "--campaign",
            campaign,
            "--profiles",
            &document.profiles.join(","),
            "--workers",
            &workers.to_string(),
            "--batch",
            &document.batch.to_string(),
            "--wall",
            &document.wall.to_string(),
            "--for",
            &document.stint.to_string(),
            "--memory",
            &document.memory.to_string(),
            "--processes",
            &document.processes.to_string(),
            "--cgroup-root",
            &self.layout.campaign.to_string_lossy(),
        ]
        .map(str::to_owned)
        .into();
        for (key, count) in &document.counts {
            args.push("--set".into());
            args.push(format!("{key}={count}"));
        }
        args
    }

    fn sweep(
        &mut self,
        assignment: &Assignment,
        campaign: &str,
        workers: u64,
    ) -> Result<(), String> {
        let wait = Duration::from_secs(assignment.document.stint);
        let args = self.sweep_args(assignment, campaign, workers);
        let started = Instant::now();
        let before = usage(&self.layout.sweep());
        let spawned = child::spawn(
            "sweep",
            &build::campaign(&self.options.state, assignment.build()),
            &args,
            &logs(&self.options.state),
        );
        let mut sweep = match spawned {
            Ok(sweep) => sweep,
            Err(error) => {
                self.sample = None;
                let reason = format!("campaign sweep did not start: {error}");
                self.record_failure(campaign, wait)?;
                return self.pause(Phase::Waiting, reason, wait);
            }
        };
        self.sweep_due = started.checked_add(sweep_limit(&assignment.document));
        let watched = self.watch(campaign, &mut sweep);
        self.sweep_due = None;
        let code = match watched {
            Ok(code) => code,
            Err(error) => {
                if let Some(confirming) = &mut self.confirm {
                    confirming.child.terminate();
                }
                sweep.stop();
                return Err(error);
            }
        };
        let cpu = used(before, usage(&self.layout.sweep()));
        let wall = started.elapsed();
        let wall_usec = u64::try_from(wall.as_micros()).unwrap_or(u64::MAX);
        let capacity = host::online_cpus().saturating_mul(wall_usec);
        self.exits.insert("sweep".into(), code);
        let stopping = signal::stopping();
        let root = self.root_mut(campaign)?;
        if let Some(cpu) = cpu {
            root.cpu_usec = root.cpu_usec.saturating_add(cpu);
            root.capacity_usec = root.capacity_usec.saturating_add(capacity);
        }
        let stint = root.stints;
        let accepted = matches!(code, 0 | 1);
        if accepted {
            root.failures = 0;
            root.alarm = code == 1;
        }
        let swept = root.clone();
        let failed = !accepted && !stopping;
        // The exit's outcome is saved before the observation, which can take
        // a minute, so a kill during it keeps the CPU sums, the failure
        // count and the retry wait.
        if failed {
            self.record_failure(campaign, wait)?;
        } else {
            self.save()?;
        }
        self.observed = Some(snapshot::observe(
            &self.options.state,
            &swept,
            Halt::At(deadline(OBSERVE_WAIT)),
        ));
        if failed {
            self.sample = None;
            let reason = format!("campaign sweep exited {code}: {}", sweep.reason());
            return self.pause(Phase::Waiting, reason, wait);
        }
        self.sample = cpu.map(|cpu| Sample {
            stint,
            cpu,
            capacity,
        });
        self.write_health();
        Ok(())
    }

    fn watch(&mut self, campaign: &str, sweep: &mut Child) -> Result<i32, String> {
        let root = self.root_mut(campaign)?;
        root.stints = root
            .stints
            .checked_add(1)
            .ok_or_else(|| format!("root {campaign} has no stint number left"))?;
        root.retry = None;
        self.save()?;
        self.phase = Phase::Sweeping;
        self.reason = None;
        self.write_health();
        loop {
            if signal::stopping() {
                sweep.terminate();
            }
            match sweep.try_exit() {
                Ok(Some(code)) => return Ok(code),
                Ok(None) => {}
                Err(error) => return Err(format!("waiting for campaign sweep: {error}")),
            }
            self.tick()?;
            std::thread::sleep(POLL);
        }
    }

    /// Counts one failed sweep of `campaign` and saves a retry wait of
    /// `wait` on this boot's clock.
    fn record_failure(&mut self, campaign: &str, wait: Duration) -> Result<(), String> {
        let wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        let retry = Retry {
            boot: host::boot_id(),
            until_ms: host::boot_ms().saturating_add(wait_ms),
        };
        let root = self.root_mut(campaign)?;
        root.failures = root.failures.saturating_add(1);
        root.retry = Some(retry);
        self.save()
    }

    fn pause(&mut self, phase: Phase, reason: String, wait: Duration) -> Result<(), String> {
        self.phase = phase;
        self.reason = Some(reason);
        self.write_health();
        let until = deadline(wait);
        let unassigned = self.assignment.is_none();
        while !signal::stopping() && Instant::now() < until {
            self.tick()?;
            let released = match phase {
                Phase::Held => self
                    .current()
                    .is_some_and(|root| !matches!(root.confirmation, Confirmation::Held(_))),
                Phase::Blocked => unassigned && self.adopted,
                _ => false,
            };
            if released {
                break;
            }
            std::thread::sleep(POLL);
        }
        Ok(())
    }

    fn tick(&mut self) -> Result<(), String> {
        if signal::stopping()
            && let Some(confirming) = &mut self.confirm
        {
            confirming.child.terminate();
        }
        self.reap_confirm()?;
        self.poll_pass()?;
        self.poll_docs()?;
        self.poll_fetch()?;
        self.poll_record();
        self.start_fetch();
        if self.confirm.is_none()
            && !signal::stopping()
            && let Some(campaign) = self.next_confirm()
        {
            self.start_confirm(&campaign)?;
        }
        let heartbeat = (self.stint_length() / 2).clamp(HEARTBEAT_MIN, HEARTBEAT_MAX);
        if self
            .health_written
            .is_none_or(|written| written.elapsed() >= heartbeat)
        {
            self.write_health();
        }
        self.start_record();
        Ok(())
    }

    fn next_confirm(&mut self) -> Option<String> {
        let current = self.current().map(Root::campaign);
        let earlier = self.next_earlier(current.as_deref());
        let order = if current.is_some() && self.last_confirmed == current {
            [(earlier, true), (current, false)]
        } else {
            [(current, false), (earlier, true)]
        };
        for (campaign, is_earlier) in order {
            let Some(campaign) = campaign else { continue };
            // Returning the current campaign first leaves `earlier_cursor`
            // unchanged, preserving the earlier campaign's turn.
            if is_earlier {
                self.earlier_cursor = Some(campaign.clone());
            }
            if self.wants_confirm(&campaign) {
                return Some(campaign);
            }
        }
        None
    }

    fn next_earlier(&self, current: Option<&str>) -> Option<String> {
        let own = |(campaign, root): &(&String, &Root)| {
            root.instance == self.instance && !root.deleting && Some(campaign.as_str()) != current
        };
        let after = self.earlier_cursor.as_deref().and_then(|cursor| {
            self.state
                .roots
                .range::<str, _>((Bound::Excluded(cursor), Bound::Unbounded))
                .find(own)
        });
        after
            .or_else(|| self.state.roots.iter().find(own))
            .map(|(campaign, _)| campaign.clone())
    }

    fn wants_confirm(&mut self, campaign: &str) -> bool {
        let Some(root) = self.state.roots.get(campaign) else {
            return false;
        };
        if root.instance != self.instance
            || self.fetching_build(&root.build)
            || root.confirm_slots > self.options.host.confirm_slots
            || self
                .confirm_after
                .get(campaign)
                .is_some_and(|after| Instant::now() < *after)
        {
            return false;
        }
        let root = root.clone();
        let current = self.state.current.as_deref() == Some(campaign);
        match &root.confirmation {
            Confirmation::Held(_) => !(current && self.phase == Phase::Sweeping),
            Confirmation::Backlog(_) => {
                self.unread(&root) == Some(true) || (!current && root.pending)
            }
            Confirmation::Failed(_) => true,
            Confirmation::Idle => root.pending || self.unread(&root) == Some(true),
        }
    }

    fn root_dir(&self, root: &Root) -> PathBuf {
        state::roots(&self.options.state).join(root.campaign())
    }

    fn unread(&mut self, root: &Root) -> Option<bool> {
        let dir = self.root_dir(root);
        let lines = self.lines.entry(root.campaign()).or_default();
        // A list that cannot be read starts a confirm, so `campaign` names
        // the fault. `campaign` reads a symlink at the list's path without
        // a fault, so that list starts none; the store pass names it under
        // `upload_error` and keeps the root.
        let count = match lines.scan(&dir.join("suspects.jsonl"), lines::BUDGET) {
            Ok(count) => count,
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return None,
            Err(_) => return Some(true),
        };
        let Ok(confirmed) = snapshot::confirmed(&dir) else {
            return Some(true);
        };
        if count.lines > confirmed {
            Some(true)
        } else if count.complete {
            Some(false)
        } else {
            None
        }
    }

    fn start_confirm(&mut self, campaign: &str) -> Result<(), String> {
        let root = self.root(campaign)?.clone();
        if let Err(reason) = build::verify_recorded(&self.options.state, &root.build) {
            return self.confirmed(campaign, Some(Confirmation::Failed(reason)), false);
        }
        let group = match cgroup::make_confirm_root(&self.layout, &root.nonce) {
            Ok(group) => group,
            Err(error) => {
                let reason = format!("the confirmation cgroup: {error}");
                return self.confirmed(campaign, Some(Confirmation::Failed(reason)), false);
            }
        };
        self.root_mut(campaign)?.pending = true;
        self.save()?;
        self.confirmed_since.insert(campaign.to_owned());
        let args: Vec<String> = [
            "confirm",
            "--root",
            &self.root_dir(&root).to_string_lossy(),
            "--archive",
            &build::archive(&self.options.state, &root.build).to_string_lossy(),
            "--slots",
            &root.confirm_slots.to_string(),
            "--cgroup-root",
            &group.to_string_lossy(),
        ]
        .map(str::to_owned)
        .into();
        match child::spawn(
            "confirm",
            &build::campaign(&self.options.state, &root.build),
            &args,
            &logs(&self.options.state),
        ) {
            Ok(child) => {
                self.confirm = Some(Confirming {
                    child,
                    campaign: campaign.to_owned(),
                });
                self.last_confirmed = Some(campaign.to_owned());
                self.write_health();
                Ok(())
            }
            Err(error) => {
                let reason = format!("campaign confirm did not start: {error}");
                self.confirmed(campaign, Some(Confirmation::Failed(reason)), false)
            }
        }
    }

    fn reap_confirm(&mut self) -> Result<(), String> {
        let Some(mut confirming) = self.confirm.take() else {
            return Ok(());
        };
        let code = match confirming.child.try_exit() {
            Ok(Some(code)) => code,
            Ok(None) => {
                self.confirm = Some(confirming);
                return Ok(());
            }
            Err(error) => {
                self.confirm = Some(confirming);
                return Err(format!("waiting for campaign confirm: {error}"));
            }
        };
        self.finish_confirm(&confirming, code)
    }

    fn finish_confirm(&mut self, confirming: &Confirming, code: i32) -> Result<(), String> {
        self.exits.insert("confirm".into(), code);
        self.confirm_exit_root = Some(confirming.campaign.clone());
        if confirming.child.terminated() {
            self.write_health();
            return Ok(());
        }
        let report = report(confirming.child.stdout_path());
        let dispatch = report.as_ref().and_then(|report| report.dispatch.clone());
        let reason = format!(
            "campaign confirm exited {code}: {}",
            confirming.child.reason()
        );
        let outcome = match code {
            0 => dispatch
                .as_deref()
                .filter(|dispatch| *dispatch != INTERRUPTED)
                .map(|_| Confirmation::Idle),
            4 if backlog_only(report.as_ref(), confirming.child.stderr().as_deref()) => {
                Some(Confirmation::Backlog(reason))
            }
            4 => Some(Confirmation::Held(reason)),
            _ => Some(Confirmation::Failed(reason)),
        };
        let drained = code == 0 && dispatch.as_deref() == Some(QUEUE_EMPTY);
        self.confirmed(&confirming.campaign, outcome, drained)
    }

    fn confirmed(
        &mut self,
        campaign: &str,
        outcome: Option<Confirmation>,
        drained: bool,
    ) -> Result<(), String> {
        let stint = self.stint_length();
        if let Some(root) = self.state.roots.get_mut(campaign) {
            let settled = outcome.is_some();
            if let Some(outcome) = outcome {
                root.confirmation = match (&root.confirmation, outcome) {
                    (
                        Confirmation::Held(_),
                        Confirmation::Backlog(reason) | Confirmation::Failed(reason),
                    ) => Confirmation::Held(reason),
                    (_, outcome) => outcome,
                };
            }
            if drained {
                root.pending = false;
            }
            if !settled || root.confirmation != Confirmation::Idle || root.pending {
                self.confirm_after
                    .insert(campaign.to_owned(), deadline(stint));
            } else {
                self.confirm_after.remove(campaign);
            }
            self.save()?;
        }
        self.write_health();
        Ok(())
    }

    fn write_health(&mut self) -> bool {
        let root = self.current();
        let current = root.map(Root::campaign);
        let held: Vec<String> = self
            .state
            .roots
            .iter()
            .filter(|(campaign, other)| {
                other.instance == self.instance
                    && Some(*campaign) != current.as_ref()
                    && matches!(other.confirmation, Confirmation::Held(_))
            })
            .map(|(campaign, _)| campaign.clone())
            .collect();
        let confirming = self
            .confirm
            .as_ref()
            .map(|confirming| confirming.campaign.clone());
        let health = Health {
            format: Some(1),
            written: Some(host::now_s()),
            instance: Some(self.instance.clone()),
            build: root.map(|root| root.build.clone()),
            root: current.clone(),
            assignment: self.state.assignment.clone(),
            assignment_error: self.assignment_error.clone(),
            upload_error: match (&self.upload_error, &self.record_error) {
                (Some(roots), Some(record)) => Some(format!("{record}; {roots}")),
                (roots, record) => record.clone().or_else(|| roots.clone()),
            },
            fetch_error: self.fetch_error.clone(),
            cleanup_error: self.cleanup_error.clone(),
            stint: root.map(|root| root.stints),
            stint_seconds: self.stint_seconds(),
            phase: Some(self.phase.name().to_owned()),
            reason: self.reason.clone(),
            sweep_overdue: Some(self.sweep_due.is_some_and(|due| Instant::now() >= due)),
            exits: Some(self.exits.clone()),
            alarm: root.map(|root| root.alarm),
            confirmation: root.map(|root| {
                if confirming.is_some()
                    && confirming == current
                    && root.confirmation == Confirmation::Idle
                {
                    "running".to_owned()
                } else {
                    root.confirmation.name().to_owned()
                }
            }),
            confirmation_reason: root
                .and_then(|root| root.confirmation.reason().map(str::to_owned)),
            confirming,
            confirm_exit_root: self.confirm_exit_root.clone(),
            held_roots: Some(held.len() as u64),
            held_root_names: Some(held.into_iter().take(HELD_NAMES).collect()),
            share_stint: self.sample.as_ref().map(|sample| sample.stint),
            stint_cpu_usec: self.sample.as_ref().map(|sample| sample.cpu),
            stint_capacity_usec: self.sample.as_ref().map(|sample| sample.capacity),
            cpu_usec: root.map(|root| root.cpu_usec),
            capacity_usec: root.map(|root| root.capacity_usec),
        };
        let saved = health::save(&self.options.state, &health);
        if let Err(error) = &saved {
            eprintln!("sim-host run: {error}");
        }
        self.health_written = Some(Instant::now());
        saved.is_ok()
    }

    fn final_upload(&mut self, until: Instant) {
        let mut input = pass::Input {
            bucket: self.bucket.halted_by(Halt::At(until)),
            state: self.options.state.clone(),
            instance: self.instance.clone(),
            roots: self.state.roots.clone(),
            current: self.state.current.clone(),
            assigned: None,
            confirming: None,
            observed: self.observed.take(),
            at_rest: true,
            stint_seconds: self.stint_seconds(),
        };
        let output = pass::pass(&mut input);
        self.record_uploads(&output);
    }

    fn stop(&mut self) {
        if let Some(mut confirming) = self.confirm.take() {
            confirming.child.terminate();
            if let Some(code) = confirming.child.stop()
                && let Err(error) = self.finish_confirm(&confirming, code)
            {
                eprintln!("sim-host run: {error}");
            }
        }
        if let Some(pass) = self.pass.take() {
            let _ = pass.join();
        }
        if let Some(docs) = self.docs.take() {
            let _ = docs.join();
        }
        if let Some(fetching) = self.fetch.take() {
            let _ = fetching.handle.join();
        }
        if let Some(record) = self.record.take() {
            let _ = record.join();
        }
        let (snapshots, until) = stop_deadlines(Instant::now());
        self.final_upload(snapshots);
        self.phase = Phase::Stopped;
        self.record_error = None;
        if !self.write_health() {
            return;
        }
        let bucket = self.bucket.halted_by(Halt::At(until));
        if let Err(error) = health::upload(&bucket, &self.options.state, &self.instance) {
            eprintln!("sim-host run: {error}");
            self.record_error = Some(error);
            self.write_health();
        }
    }

    fn start_record(&mut self) {
        if !self.record_due() || !self.write_health() {
            return;
        }
        self.record_started = Some((Instant::now(), self.stint_seconds()));
        let bucket = self.bucket.clone();
        let state = self.options.state.clone();
        let instance = self.instance.clone();
        self.record = Some(std::thread::spawn(move || {
            health::upload(&bucket, &state, &instance)
        }));
    }

    /// When unassigned, the period is `IDLE / 2`. After the prior upload
    /// is collected, a changed stint length makes the next upload due; a
    /// stop request makes `record_due` return `false`.
    fn record_due(&self) -> bool {
        let stint = self.stint_seconds();
        let paced = match self.record_stored {
            Some(stored) if stored != stint => stored
                .map_or(IDLE, Duration::from_secs)
                .min(self.stint_length()),
            _ => self.stint_length(),
        };
        self.record.is_none()
            && !signal::stopping()
            && self.record_started.is_none_or(|(started, started_stint)| {
                started_stint != stint || started.elapsed() >= record_period(paced)
            })
    }

    fn poll_record(&mut self) {
        if !self.record.as_ref().is_some_and(JoinHandle::is_finished) {
            return;
        }
        let uploaded = self
            .record
            .take()
            .expect("a finished upload")
            .join()
            .unwrap_or_else(|_| Err("the upload of the record panicked".to_owned()));
        match uploaded {
            Ok(()) => {
                self.record_stored = self.record_started.map(|(_, stint)| stint);
                if self.record_error.take().is_some() {
                    self.record_started = None;
                }
            }
            Err(error) if signal::stopping() => drop(error),
            Err(error) => self.record_error = Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;
    use std::time::{Duration, Instant};

    use super::{
        Report, Runner, Usage, backlog_only, record_period, report, retry_wait, stop_deadlines,
        used,
    };
    use crate::assignment::Document;
    use crate::build::{self, Commit};
    use crate::cgroup::Layout;
    use crate::cli::{Host, Run};
    use crate::health::Phase;
    use crate::state::{Confirmation, Retry, Root, State};
    use crate::store::Bucket;

    const INSTANCE: &str = "i-0123abcd";

    fn runner(state: &Path) -> Runner {
        Runner {
            options: Run {
                state: state.to_owned(),
                disk_reserve: 0,
                system_memory: 0,
                host: Host {
                    bucket: "bucket".into(),
                    cgroup: None,
                    confirm_slots: 1,
                    system_cores: 0,
                },
            },
            bucket: Bucket::new("bucket"),
            instance: INSTANCE.to_owned(),
            layout: Layout::of(&state.join("cgroup")),
            state: State {
                format: 1,
                ..State::default()
            },
            latest: None,
            fetched: None,
            assignment: None,
            assignment_error: None,
            upload_error: None,
            fetch_error: None,
            cleanup_error: None,
            pass: None,
            docs: None,
            fetch: None,
            fetch_after: None,
            adopted: false,
            observed: None,
            confirmed_since: BTreeSet::new(),
            confirm: None,
            confirm_after: BTreeMap::new(),
            lines: BTreeMap::new(),
            earlier_cursor: None,
            last_confirmed: None,
            confirm_exit_root: None,
            exits: BTreeMap::new(),
            phase: Phase::Sweeping,
            reason: None,
            sample: None,
            sweep_due: None,
            health_written: None,
            record: None,
            record_started: None,
            record_stored: None,
            record_error: None,
        }
    }

    fn unconfirmed_root(runner: &mut Runner, nonce: &str) -> String {
        let state = runner.options.state.clone();
        let build = crate::file::sha256(b"b");
        let archive = build::archive(&state, &build);
        std::fs::create_dir_all(&archive).expect("the archive directory");
        std::fs::write(archive.join("build"), "b").expect("the build record");
        std::fs::write(build::campaign(&state, &build), "c").expect("the binary");
        let commit = Commit {
            format: 1,
            commit: "a".repeat(40),
            build: build.clone(),
            campaign: crate::file::sha256(b"c"),
        };
        let record = serde_json::to_vec(&commit).expect("the commit record");
        std::fs::write(build::record(&state, &build), record).expect("the commit record");
        let root = Root {
            name: "sim".into(),
            instance: INSTANCE.into(),
            nonce: nonce.repeat(16),
            build,
            counts: BTreeMap::new(),
            confirm_slots: 1,
            stints: 1,
            failures: 0,
            cpu_usec: 0,
            capacity_usec: 0,
            alarm: false,
            confirmation: Confirmation::Idle,
            pending: false,
            retry: None,
            deleting: false,
        };
        let campaign = root.campaign();
        let dir = crate::state::roots(&state).join(&campaign);
        std::fs::create_dir_all(&dir).expect("the root directory");
        std::fs::write(dir.join("suspects.jsonl"), "{}\n").expect("a suspect line");
        runner.state.roots.insert(campaign.clone(), root);
        campaign
    }

    #[test]
    fn earlier_roots_take_turns_between_confirms_of_the_current_root() {
        let dir = crate::file::scratch("turns");
        let mut runner = runner(&dir);
        let first = unconfirmed_root(&mut runner, "00");
        let second = unconfirmed_root(&mut runner, "11");
        let current = unconfirmed_root(&mut runner, "22");
        runner.state.current = Some(current.clone());
        let mut confirms = Vec::new();
        for _ in 0..6 {
            let campaign = runner.next_confirm().expect("a root wants a confirm");
            // Setting `last_confirmed` models a started confirmation before
            // the next poll.
            runner.last_confirmed = Some(campaign.clone());
            confirms.push(campaign);
        }
        assert_eq!(
            confirms,
            [&current, &first, &current, &second, &current, &first].map(String::as_str)
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_failed_confirmation_is_retried_without_queued_jobs_or_a_new_line() {
        let dir = crate::file::scratch("failed-retry");
        let mut runner = runner(&dir);
        let campaign = unconfirmed_root(&mut runner, "00");
        let confirm = crate::state::roots(&dir).join(&campaign).join("confirm");
        std::fs::create_dir_all(&confirm).expect("the confirm directory");
        std::fs::write(confirm.join("confirmed"), "1").expect("the cursor");
        assert!(!runner.wants_confirm(&campaign), "an idle root is settled");
        let root = runner.state.roots.get_mut(&campaign).expect("the root");
        root.confirmation = Confirmation::Failed("the archive was missing".into());
        assert!(runner.wants_confirm(&campaign));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    fn assign(runner: &mut Runner, stint: u64) {
        runner.assignment = Some(crate::assignment::Assignment {
            document: Document {
                format: 1,
                name: "sim".into(),
                profiles: vec!["a".into()],
                counts: BTreeMap::new(),
                batch: 30,
                wall: 600,
                memory: 1 << 30,
                processes: 64,
                stint,
            },
            commit: Commit {
                format: 1,
                commit: "a".repeat(40),
                build: crate::file::sha256(b"b"),
                campaign: crate::file::sha256(b"c"),
            },
        });
    }

    /// An upload starts within half a stint length and within 300 seconds
    /// of the last when the tick runs on time, and at once after a change
    /// of the stint length in force.
    #[test]
    fn the_record_is_uploaded_every_half_stint_and_every_300_seconds() {
        for (stint, period) in [(2, 900), (60, 29_900), (600, 299_900), (3_600, 299_900)] {
            assert_eq!(
                record_period(Duration::from_secs(stint)),
                Duration::from_millis(period),
                "{stint}"
            );
        }
        let dir = crate::file::scratch("record-due");
        let mut runner = runner(&dir);
        let ago = |seconds: u64| {
            Instant::now()
                .checked_sub(Duration::from_secs(seconds))
                .expect("a past instant")
        };
        assert!(runner.record_due(), "the first upload");
        runner.record_started = Some((ago(29), None));
        assert!(!runner.record_due(), "unassigned, before 30 seconds");
        runner.record_started = Some((ago(30), None));
        assert!(runner.record_due(), "unassigned, at 30 seconds");
        assign(&mut runner, 3_600);
        runner.record_started = Some((ago(299), Some(3_600)));
        assert!(!runner.record_due(), "a long stint, before 300 seconds");
        runner.record_started = Some((ago(300), Some(3_600)));
        assert!(runner.record_due(), "a long stint, at 300 seconds");
        for earlier in [None, Some(2)] {
            runner.record_started = Some((Instant::now(), earlier));
            assert!(
                runner.record_due(),
                "after the stint changed from {earlier:?}"
            );
        }
        runner.record_started = Some((ago(2), Some(3_600)));
        runner.record_stored = Some(Some(2));
        assert!(
            runner.record_due(),
            "a retry under a raised stint is paced by the stint the bucket's record states"
        );
        runner.record_stored = Some(None);
        assert!(
            !runner.record_due(),
            "a stored unassigned record paces at 30 seconds"
        );
        runner.record_started = Some((ago(30), Some(3_600)));
        assert!(runner.record_due());
        runner.record_stored = Some(Some(3_600));
        assert!(!runner.record_due(), "the stored stint is the one in force");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// The snapshots of a stop end 15 seconds before the stopped record's
    /// put, and both end within the 120 seconds of the final wait.
    #[test]
    fn the_stopped_record_keeps_the_last_15_seconds_of_the_final_wait() {
        let start = Instant::now();
        let (snapshots, record) = stop_deadlines(start);
        assert_eq!(record - start, Duration::from_secs(120));
        assert_eq!(record - snapshots, Duration::from_secs(15));
    }

    /// A successful upload that clears an earlier error makes the next
    /// upload due at once, so the stored record stops naming the error; a
    /// success with no earlier error leaves the period in force.
    #[test]
    fn an_upload_that_clears_an_error_is_followed_at_once() {
        let dir = crate::file::scratch("record-rearm");
        let mut runner = runner(&dir);
        for (error, due) in [(Some("hosts/x: refused"), true), (None, false)] {
            runner.record_error = error.map(str::to_owned);
            runner.record_started = Some((Instant::now(), None));
            let upload = std::thread::spawn(|| Ok(()));
            while !upload.is_finished() {
                std::thread::yield_now();
            }
            runner.record = Some(upload);
            runner.poll_record();
            assert_eq!(runner.record_error, None);
            assert_eq!(runner.record_stored, Some(None));
            assert_eq!(runner.record_due(), due, "{error:?}");
        }
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// The saved `upload_error` names a failed record upload while store
    /// passes succeed or fail, and the cut to the text bound keeps it.
    #[test]
    fn a_store_pass_leaves_the_record_error_named() {
        let dir = crate::file::scratch("record-error");
        let mut runner = runner(&dir);
        let record = "hosts/i-0123abcd/health.json: refused";
        runner.record_error = Some(record.to_owned());
        let saved = |runner: &mut Runner, errors: Vec<String>| {
            runner.record_uploads(&crate::pass::Output {
                errors,
                deletable: Vec::new(),
            });
            runner.write_health();
            let bytes = crate::file::read(&crate::health::path(&dir), crate::health::BOUND)
                .expect("the record reads")
                .expect("the record exists");
            let health: crate::health::Health =
                serde_json::from_slice(&bytes).expect("the record parses");
            health.upload_error.unwrap_or_default()
        };
        assert_eq!(saved(&mut runner, Vec::new()), record);
        let roots = "roots/sim/status.json: refused".to_owned();
        let both = saved(&mut runner, vec![roots.clone()]);
        assert!(both.contains(record) && both.contains(&roots), "{both}");
        let long = "r".repeat(crate::health::TEXT_MAX + 1);
        assert!(saved(&mut runner, vec![long]).starts_with(record));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_linked_list_starts_no_confirm_and_an_unreadable_one_starts_one() {
        let dir = crate::file::scratch("linked-list");
        let mut runner = runner(&dir);
        let campaign = unconfirmed_root(&mut runner, "00");
        let list = crate::state::roots(&dir)
            .join(&campaign)
            .join("suspects.jsonl");
        let outside = dir.join("outside");
        std::fs::write(&outside, "{}\n").expect("a list outside the root");
        std::fs::remove_file(&list).expect("the list");
        std::os::unix::fs::symlink(&outside, &list).expect("a link");
        for _ in 0..3 {
            assert!(!runner.wants_confirm(&campaign), "a linked list");
        }
        std::fs::remove_file(&list).expect("the link");
        std::fs::create_dir(&list).expect("a directory at the list");
        assert!(runner.wants_confirm(&campaign), "an unreadable list");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn cpu_is_measured_only_from_two_readings_of_one_counter() {
        assert_eq!(used(Usage::Absent, Usage::Absent), Some(0));
        assert_eq!(used(Usage::Absent, Usage::Value(7)), Some(7));
        assert_eq!(used(Usage::Value(5), Usage::Value(12)), Some(7));
        assert_eq!(used(Usage::Value(12), Usage::Value(5)), None);
        assert_eq!(used(Usage::Value(5), Usage::Absent), None);
        assert_eq!(used(Usage::Unknown, Usage::Value(5)), None);
        assert_eq!(used(Usage::Value(5), Usage::Unknown), None);
    }

    #[test]
    fn a_retry_waits_its_remainder_on_one_boot_and_a_full_stint_after_a_reboot() {
        let retry = |until_ms| Retry {
            boot: "a".into(),
            until_ms,
        };
        assert_eq!(retry_wait(None, "a", 50, 1_000), (0, None));
        assert_eq!(retry_wait(Some(&retry(400)), "a", 100, 1_000), (300, None));
        assert_eq!(retry_wait(Some(&retry(100)), "a", 100, 1_000), (0, None));
        assert_eq!(retry_wait(Some(&retry(50)), "a", 100, 1_000), (0, None));
        let cut = Retry {
            boot: "a".into(),
            until_ms: 1_100,
        };
        assert_eq!(
            retry_wait(Some(&retry(u64::MAX)), "a", 100, 1_000),
            (1_000, Some(cut))
        );
        let rebooted = Retry {
            boot: "b".into(),
            until_ms: 1_005,
        };
        assert_eq!(
            retry_wait(Some(&retry(10)), "b", 5, 1_000),
            (1_000, Some(rebooted))
        );
    }

    #[test]
    fn only_a_report_held_by_backlog_alone_is_a_backlog() {
        let hold = "backlog holds 64 failure pins without a resolved disposition at limit 64; \
                    dispose findings or raise backlog";
        let report_of = |refusals: &[&str], rejections: &[&str]| Report {
            dispatch: Some("held".into()),
            refusals: Some(refusals.iter().map(|text| (*text).to_owned()).collect()),
            rejections: Some(rejections.iter().map(|text| (*text).to_owned()).collect()),
        };
        assert!(backlog_only(Some(&report_of(&[hold], &[])), Some("")));
        assert!(backlog_only(Some(&report_of(&[hold, hold], &[])), Some("")));
        assert!(!backlog_only(
            Some(&report_of(&[hold, "custody holds"], &[])),
            Some("")
        ));
        assert!(!backlog_only(
            Some(&report_of(&[hold], &["a rejection"])),
            Some("")
        ));
        assert!(!backlog_only(
            Some(&report_of(&[], &[])),
            Some("raise backlog")
        ));
        assert!(!backlog_only(
            Some(&report_of(&[hold], &[])),
            Some(&format!("{hold}; omitted refusals: 3"))
        ));
        assert!(!backlog_only(Some(&Report::default()), Some("")));
        assert!(!backlog_only(Some(&report_of(&[hold], &[])), None));
        assert!(!backlog_only(None, Some(hold)));
    }

    #[test]
    fn a_report_longer_than_a_log_tail_parses_and_a_cut_one_does_not() {
        let dir = crate::file::scratch("report");
        let path = dir.join("confirm.out");
        let findings = "f".repeat(256 << 10);
        let text = serde_json::json!({
            super::DISPATCH: super::QUEUE_EMPTY, "refusals": [], "rejections": [],
            "findings": {"rows": [findings]},
        })
        .to_string();
        std::fs::write(&path, format!("{text}\n")).expect("a report");
        let parsed = report(&path).expect("it parses");
        assert_eq!(parsed.dispatch.as_deref(), Some(super::QUEUE_EMPTY));
        assert_eq!(parsed.refusals, Some(Vec::new()));
        std::fs::write(&path, &text[..text.len() / 2]).expect("a cut report");
        assert!(report(&path).is_none());
        std::fs::write(&path, "").expect("no report");
        assert!(report(&path).is_none());
        let padded = |length: u64| {
            let mut bytes = format!("{text}\n").into_bytes();
            bytes.resize(usize::try_from(length).expect("a length"), b' ');
            std::fs::write(&path, bytes).expect("a padded report");
        };
        padded(super::REPORT_MAX);
        assert!(report(&path).is_some(), "a report at the bound");
        padded(super::REPORT_MAX + 1);
        assert!(report(&path).is_none(), "a report past the bound");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_sweep_is_due_after_its_stint_its_wall_limit_and_the_grace() {
        let document = Document {
            format: 1,
            name: "sim".into(),
            profiles: vec!["a".into()],
            counts: BTreeMap::new(),
            batch: 30,
            wall: 600,
            memory: 1 << 30,
            processes: 64,
            stint: 3_600,
        };
        assert_eq!(
            super::sweep_limit(&document),
            Duration::from_secs(3_600 + 600 + 300)
        );
        let longest = Document {
            wall: crate::assignment::SECONDS_MAX,
            stint: crate::assignment::SECONDS_MAX,
            ..document
        };
        assert_eq!(
            super::sweep_limit(&longest),
            Duration::from_secs(2 * crate::assignment::SECONDS_MAX + 300)
        );
    }

    #[test]
    fn a_copies_directory_that_cannot_be_listed_is_named_under_cleanup_error() {
        let dir = crate::file::scratch("copies-listing");
        let mut runner = runner(&dir);
        runner.state.assignment = Some(crate::file::sha256(b"copy"));
        let copies = crate::state::assignments(&dir);
        std::fs::write(&copies, "").expect("a file in place of the directory");
        runner.finish_deletions().expect("the pass ends");
        let error = runner.cleanup_error.clone().unwrap_or_default();
        assert!(error.contains(&copies.display().to_string()), "{error:?}");
        std::fs::remove_file(&copies).expect("the file is removed");
        crate::file::private_dir(&copies).expect("the directory");
        runner.finish_deletions().expect("the pass ends");
        assert_eq!(runner.cleanup_error, None);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn an_old_copy_is_removed_and_a_directory_under_a_copys_name_stays() {
        let dir = crate::file::scratch("copies-kinds");
        let mut runner = runner(&dir);
        let kept = crate::file::sha256(b"kept");
        runner.state.assignment = Some(kept.clone());
        let copies = crate::state::assignments(&dir);
        crate::file::private_dir(&copies).expect("the copies");
        std::fs::write(copies.join(format!("{kept}.json")), "kept").expect("the kept copy");
        let old = copies.join(format!("{}.json", crate::file::sha256(b"old")));
        std::fs::write(&old, "old").expect("an old copy");
        let staged = copies.join(format!(".{}.json.staged", crate::file::sha256(b"staged")));
        std::fs::write(&staged, "staged").expect("a staged copy");
        let named = copies.join(format!("{}.json", crate::file::sha256(b"dir")));
        std::fs::create_dir(&named).expect("a directory under a copy's name");
        std::fs::write(named.join("sentinel"), "x").expect("a sentinel");
        runner.finish_deletions().expect("the pass ends");
        assert!(!old.exists() && !staged.exists(), "old copies are removed");
        assert!(
            copies.join(format!("{kept}.json")).exists(),
            "the kept copy stays"
        );
        assert_eq!(
            std::fs::read(named.join("sentinel")).expect("the sentinel"),
            b"x"
        );
        let error = runner.cleanup_error.clone().unwrap_or_default();
        assert!(error.contains(&named.display().to_string()), "{error:?}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_marked_root_path_that_is_no_directory_is_removed_by_itself() {
        for kind in ["link", "file", "fifo"] {
            let dir = crate::file::scratch(&format!("marked-{kind}"));
            let mut runner = runner(&dir);
            let campaign = unconfirmed_root(&mut runner, "00");
            runner
                .state
                .roots
                .get_mut(&campaign)
                .expect("the root")
                .deleting = true;
            crate::file::private_dir(&crate::snapshot::uploads(&dir)).expect("the uploads");
            let root = crate::state::roots(&dir).join(&campaign);
            std::fs::remove_dir_all(&root).expect("the root directory is removed");
            let sentinel = dir.join("sentinel");
            std::fs::create_dir(&sentinel).expect("a sentinel directory");
            std::fs::write(sentinel.join("file"), b"x").expect("a sentinel file");
            match kind {
                "link" => std::os::unix::fs::symlink(&sentinel, &root).expect("a link"),
                "file" => std::fs::write(&root, b"").expect("a file"),
                _ => {
                    let name = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())
                        .expect("a path");
                    // SAFETY: `name` is a NUL-terminated path.
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
            }
            runner.finish_deletions().expect("the pass ends");
            assert!(
                !crate::file::exists(&root).expect("the path is read"),
                "{kind}"
            );
            assert_eq!(
                std::fs::read(sentinel.join("file")).expect("the sentinel"),
                b"x"
            );
            assert!(!runner.state.roots.contains_key(&campaign), "{kind}");
            assert_eq!(runner.cleanup_error, None, "{kind}");
            let saved = crate::state::load(&dir).expect("state.json");
            assert!(!saved.roots.contains_key(&campaign), "{kind}");
            std::fs::remove_dir_all(&dir).expect("cleanup");
        }
    }

    #[test]
    fn a_marked_root_stays_while_another_holder_has_its_lock() {
        let dir = crate::file::scratch("held-root");
        let mut runner = runner(&dir);
        let campaign = unconfirmed_root(&mut runner, "00");
        runner
            .state
            .roots
            .get_mut(&campaign)
            .expect("the root")
            .deleting = true;
        let root = crate::state::roots(&dir).join(&campaign);
        crate::file::private_dir(&crate::snapshot::uploads(&dir)).expect("the uploads directory");
        let holder = crate::file::lock_dir(&root)
            .expect("the lock is free")
            .expect("the root directory");
        runner.finish_deletions().expect("the pass ends");
        assert!(root.join("suspects.jsonl").exists(), "the held root stays");
        assert!(runner.state.roots[&campaign].deleting);
        let error = runner.cleanup_error.clone().unwrap_or_default();
        assert!(error.contains(&campaign), "{error:?}");
        // A child another test thread forks keeps a copy of this descriptor
        // until it execs, so the lock is released explicitly.
        holder.unlock().expect("the lock is released");
        drop(holder);
        runner.finish_deletions().expect("the pass ends");
        assert!(!root.exists(), "the released root is removed");
        assert!(!runner.state.roots.contains_key(&campaign));
        assert_eq!(runner.cleanup_error, None);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_current_root_that_cannot_be_checked_is_observed_as_an_error() {
        let dir = crate::file::scratch("observe-error");
        let mut runner = runner(&dir);
        let campaign = unconfirmed_root(&mut runner, "00");
        runner.state.current = Some(campaign.clone());
        let root = crate::state::roots(&dir).join(&campaign);
        std::fs::remove_dir_all(&root).expect("the root directory is removed");
        std::fs::write(&root, "").expect("a file in place of the root");
        runner.observe_current();
        let error = match &runner.observed {
            Some(Err(error)) => error.clone(),
            other => panic!("the failed check is not observed: {other:?}"),
        };
        assert!(error.contains("sweep.json"), "{error}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn the_health_record_marks_a_sweep_that_has_passed_its_deadline() {
        let dir = crate::file::scratch("overdue");
        let mut runner = runner(&dir);
        let overdue = |runner: &mut Runner| {
            runner.write_health();
            let bytes = crate::file::read(&crate::health::path(&dir), crate::health::BOUND)
                .expect("the record reads")
                .expect("the record exists");
            let health: crate::health::Health =
                serde_json::from_slice(&bytes).expect("the record parses");
            health.sweep_overdue
        };
        assert_eq!(overdue(&mut runner), Some(false));
        runner.sweep_due = Some(Instant::now());
        assert_eq!(overdue(&mut runner), Some(true));
        runner.sweep_due = Instant::now().checked_add(Duration::from_secs(3_600));
        assert_eq!(overdue(&mut runner), Some(false));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// Each state the runner checks when it applies a pass's candidate,
    /// set one at a time on a root that is otherwise retirable.
    #[derive(Clone, Copy, Debug)]
    enum Forbidden {
        Nothing,
        Current,
        ConfirmedSince,
        AssignedBuild,
        Confirming,
        Pending,
        Locked,
        LineAfterStamp,
        CursorAfterStamp,
        CursorReplacedAtItsTime,
        SweepAfterStamp,
        FindingAfterStamp,
        StateLocked,
    }

    /// Applies one finished pass that names the root of nonce `00` deletable
    /// with the stamp taken before `forbidden` is set, and reports whether
    /// the root was marked deleting and whether its directory was removed.
    fn applied(forbidden: Forbidden) -> (bool, bool) {
        let dir = crate::file::scratch(&format!("apply-{forbidden:?}"));
        let mut runner = runner(&dir);
        let campaign = unconfirmed_root(&mut runner, "00");
        let root_dir = crate::state::roots(&dir).join(&campaign);
        std::fs::create_dir_all(root_dir.join("confirm")).expect("the confirm directory");
        std::fs::write(root_dir.join("confirm/confirmed"), "1").expect("the cursor");
        let finding = root_dir.join("confirm/state/findings/f1");
        std::fs::create_dir_all(&finding).expect("a finding directory");
        std::fs::write(root_dir.join("sweep.json"), "{}").expect("the sweep state");
        crate::file::private_dir(&crate::snapshot::uploads(&dir)).expect("the uploads directory");
        let document = Document {
            format: 1,
            name: "sim".into(),
            profiles: vec!["a".into()],
            counts: BTreeMap::new(),
            batch: 30,
            wall: 600,
            memory: 1 << 30,
            processes: 64,
            stint: 600,
        };
        let assigned = |build: String| Commit {
            format: 1,
            commit: "b".repeat(40),
            build,
            campaign: crate::file::sha256(b"d"),
        };
        runner.latest = Some((document.clone(), assigned(crate::file::sha256(b"other"))));
        let stamp = crate::snapshot::stamp(&root_dir);
        // A later write of the same length and contents is told apart by
        // its modification time.
        std::thread::sleep(Duration::from_millis(20));
        let mut holder = None;
        let root = runner.state.roots.get_mut(&campaign).expect("the root");
        match forbidden {
            Forbidden::Nothing => {}
            Forbidden::Current => runner.state.current = Some(campaign.clone()),
            Forbidden::ConfirmedSince => {
                runner.confirmed_since.insert(campaign.clone());
            }
            Forbidden::AssignedBuild => {
                runner.latest = Some((document, assigned(root.build.clone())));
            }
            Forbidden::Confirming => root.confirmation = Confirmation::Held("held".into()),
            Forbidden::Pending => root.pending = true,
            Forbidden::Locked => {
                holder = crate::file::lock_dir(&root_dir).expect("the lock is free");
            }
            Forbidden::LineAfterStamp => {
                let mut list = std::fs::OpenOptions::new()
                    .append(true)
                    .open(root_dir.join("suspects.jsonl"))
                    .expect("the suspect list");
                std::io::Write::write_all(&mut list, b"{}\n").expect("a late line");
            }
            Forbidden::CursorAfterStamp => {
                std::fs::write(root_dir.join("confirm/confirmed"), "1").expect("the cursor");
            }
            Forbidden::CursorReplacedAtItsTime => {
                let cursor = root_dir.join("confirm/confirmed");
                let modified = std::fs::metadata(&cursor)
                    .and_then(|meta| meta.modified())
                    .expect("the cursor's time");
                let staged = root_dir.join("confirm/.confirmed");
                std::fs::write(&staged, "1").expect("a same-length cursor");
                std::fs::File::options()
                    .write(true)
                    .open(&staged)
                    .and_then(|file| file.set_modified(modified))
                    .expect("the cursor's time kept");
                std::fs::rename(&staged, &cursor).expect("the cursor replaced");
            }
            Forbidden::SweepAfterStamp => {
                std::fs::write(root_dir.join("sweep.json"), "{}").expect("the sweep state");
            }
            Forbidden::FindingAfterStamp => {
                std::fs::write(finding.join("disposition"), "{}").expect("a disposition");
            }
            Forbidden::StateLocked => {
                holder = crate::file::lock_dir(&root_dir.join("confirm/state"))
                    .expect("the lock is free");
            }
        }
        let output = crate::pass::Output {
            errors: Vec::new(),
            deletable: vec![(campaign.clone(), stamp)],
        };
        runner.pass = Some(std::thread::spawn(move || output));
        while !runner.pass.as_ref().is_some_and(|pass| pass.is_finished()) {
            std::thread::sleep(Duration::from_millis(1));
        }
        runner.poll_pass().expect("the result is applied");
        assert!(runner.pass.is_none(), "the finished pass was applied");
        drop(holder);
        let marked = runner
            .state
            .roots
            .get(&campaign)
            .is_none_or(|root| root.deleting);
        if !marked {
            assert!(
                root_dir.join("suspects.jsonl").exists(),
                "the root stays whole"
            );
        }
        let removed = !root_dir.exists();
        std::fs::remove_dir_all(&dir).expect("cleanup");
        (marked, removed)
    }

    #[test]
    fn a_build_is_adopted_only_after_its_fetch_returns() {
        let dir = crate::file::scratch("adopt-after-fetch");
        let mut runner = runner(&dir);
        crate::file::private_dir(&crate::state::assignments(&dir)).expect("the copies");
        let campaign = unconfirmed_root(&mut runner, "00");
        let build = runner.state.roots[&campaign].build.clone();
        runner.state.roots.clear();
        let commit = Commit {
            format: 1,
            commit: "a".repeat(40),
            build,
            campaign: crate::file::sha256(b"c"),
        };
        assert!(runner.on_disk(&commit), "the tree is at its final path");
        let document = Document {
            format: 1,
            name: "sim".into(),
            profiles: vec!["a".into()],
            counts: BTreeMap::new(),
            batch: 30,
            wall: 600,
            memory: 1 << 30,
            processes: 64,
            stint: 600,
        };
        runner.latest = Some((document, commit.clone()));
        let (release, released) = std::sync::mpsc::channel::<()>();
        runner.fetch = Some(super::Fetching {
            commit: commit.clone(),
            handle: std::thread::spawn(move || {
                let _ = released.recv();
                Ok(())
            }),
        });
        runner.compose().expect("the stint composes");
        assert!(runner.assignment.is_none(), "a running fetch's build waits");
        runner.fetched = Some(commit.clone());
        runner.compose().expect("the stint composes");
        assert!(
            runner.assignment.is_none(),
            "a running fetch's build waits in the fetched arm too"
        );
        release.send(()).expect("the fetch returns");
        while !runner
            .fetch
            .as_ref()
            .is_some_and(|fetch| fetch.handle.is_finished())
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        runner.poll_fetch().expect("the fetch is joined");
        runner.compose().expect("the stint composes");
        assert_eq!(
            runner
                .assignment
                .as_ref()
                .map(|assignment| &assignment.commit),
            Some(&commit),
            "a returned fetch's build is adopted"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_pass_candidate_is_kept_when_any_retirement_condition_changed() {
        assert_eq!(
            applied(Forbidden::Nothing),
            (true, true),
            "a retirable root is marked and removed"
        );
        for forbidden in [
            Forbidden::Current,
            Forbidden::ConfirmedSince,
            Forbidden::AssignedBuild,
            Forbidden::Confirming,
            Forbidden::Pending,
            Forbidden::Locked,
            Forbidden::LineAfterStamp,
            Forbidden::CursorAfterStamp,
            Forbidden::CursorReplacedAtItsTime,
            Forbidden::SweepAfterStamp,
            Forbidden::FindingAfterStamp,
            Forbidden::StateLocked,
        ] {
            assert_eq!(
                applied(forbidden),
                (false, false),
                "{forbidden:?} keeps the root"
            );
        }
    }
}
