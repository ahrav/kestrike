//! `campaign fuzz` runs the archived worker's `campaign` fuzz target in
//! pens for a set time against a persistent corpus. After the workers
//! finish, the run starts the corpus merge if the stop flag is clear at
//! merge start.
//!
//! A fuzz root is a directory only this user can write, held by one
//! command at a time. `fuzz.json` holds the next run's number, the last
//! run started with its build, each failure key's count, the caught and
//! missed controls with their alarm, and the count of consecutive
//! unadopted merges of runs that reached their deadline; `findings.jsonl`
//! and `failures/ID/` hold the findings [`intake`] files, and `control/`
//! the last control's; `corpus/` is libFuzzer's output directory;
//! `runs/N/` holds run `N`'s seeds, each worker's artifact directory
//! `wK/` and output `wK.stderr`, the merge's `merge/`, `merge.txt` and
//! `merge.stderr`, and `run.json`, the run's record.
//!
//! Before [`opened`] and [`Session::advance`] write under the root, a run
//! claims the root and the pens of its delegated cgroup root, checks the
//! pens' summed limits, verifies the archive and runs the [`merging`]
//! probe. [`Session::advance`] stores the advanced run number before it
//! creates `runs/N/`, so each number names one run, a killed one included,
//! and each seed writer writes into a new directory. Before any fuzz
//! worker, [`Session::controlled`] runs the planted control through the
//! same intake and checks the worker's coverage counters, and a run whose
//! control was missed starts none. The monitor bounds each worker by
//! [`Bounds`]. SIGINT, SIGTERM, a failed worker thread, the [`FAILED`]th
//! failed worker or a failure past the key table stops the run: every
//! worker gets SIGTERM, and a merge starts only when no stop has come by
//! its start.
//! [`Session::merged`] adopts a merge by a swap whose cut by a process
//! kill [`recovered`] repairs at the next start.
//! A missed control sets the record's alarm. [`opened`] holds every
//! later start of a root whose record carries the alarm, so `control/`
//! keeps the files of the missed control.
//!
//! The run verifies the archive again, writes `run.json` and replaces
//! `fuzz.json`; a failed closing verification exits 4 and later runs of
//! the root proceed, since a fuzz root accepts any build. The command
//! replaces each record as a whole, so a reader sees a complete old or
//! new version. Outside its delegated cgroup root, a run writes only
//! under its fuzz root.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::pen::{self, Limits, Pen};
use super::{Error, archived, claim, end, fit, held, invalid, outside_archive};
use crate::record::{Provenance, Text};
use crate::store::cgroup::Root;
use crate::store::{open_host, present_host, regular_files, remove_tree, rename_host};

mod intake;

use intake::{Failure, Filed, Origin, RERUN};

/// The ending of a run whose planted control was missed, for which the
/// command exits 1.
const MISSED: &str = "control missed";

/// Whether `ran`, a run's record, ends with a missed control.
pub(in crate::campaign) fn missed(ran: &Value) -> bool {
    ran["ending"] == MISSED
}

/// The failed workers after which a run ends.
const FAILED: u64 = 16;

/// The text a worker built with libFuzzer's coverage counters prints at
/// its start.
const COUNTERS: &str = "inline 8-bit counters";

/// The default of `--memory`, each pen's memory limit in bytes.
pub(in crate::campaign) const MEMORY: u64 = 8 << 30;

/// The longest `--for`: libFuzzer reads `-max_total_time` as an `int`.
pub(in crate::campaign) const SECONDS: u64 = i32::MAX as u64;

/// The run directories a root keeps, the new run's among them.
const RUNS_KEPT: usize = 16;

const SEEDS_WAIT: Duration = Duration::from_secs(60);

/// How often the monitor reads signals, limits and output sizes.
const POLL: Duration = Duration::from_millis(100);

/// The largest `fuzz.json`, in bytes, that [`read`] accepts.
const RECORD_BOUND: u64 = 1 << 20;

/// The bytes at the end of a worker's output read for its counts line.
const TAIL: u64 = 64 << 10;

/// The bytes at the start of the control worker's output read for its
/// [`COUNTERS`] line, which libFuzzer prints as it starts.
const START: u64 = 1 << 20;

const LIMITS: [&str; 2] = ["-max_len=65536", "-timeout=60"];

/// Returns libFuzzer's `-rss_limit_mb` for the pen's byte limit: three
/// quarters of it in MiB, raised to 1 MiB when needed because 0 disables
/// the check. libFuzzer reads its RSS once a second, and the kernel
/// charges the pen for memory outside that RSS, so the gap between the
/// RSS threshold and the pen limit gives libFuzzer room to report an
/// out-of-memory input and write its artifact before the kernel kills
/// every process of the pen, a merge's outer process included.
fn rss_limit_mb(memory: u64) -> u64 {
    ((memory - memory / 4) >> 20).max(1)
}

const COUNTS: &str = "fuzz: campaign ";

/// The limits the monitor holds a run's workers and its merge to.
#[derive(Clone, Copy, Debug)]
struct Bounds {
    /// How long past the deadline, or past a stop, a worker may run.
    grace: Duration,
    merge: Duration,
    /// The bytes a worker's output file may hold.
    output: u64,
}

impl Bounds {
    /// The bound a process with `output` bytes of output has passed at
    /// `now` under its kill time `limit`: `time` takes precedence over
    /// `output`.
    fn passed(&self, now: Instant, limit: Instant, output: u64) -> Option<&'static str> {
        if now > limit {
            Some("time")
        } else {
            (output > self.output).then_some("output")
        }
    }
}

const BOUNDS: Bounds = Bounds {
    grace: Duration::from_secs(180),
    merge: Duration::from_secs(1_800),
    output: 64 << 20,
};

/// What `campaign fuzz` runs and how much of the host it uses.
pub(in crate::campaign) struct Plan {
    pub root: PathBuf,
    pub archive: PathBuf,
    /// The run's length in seconds, each worker's `-max_total_time`.
    pub seconds: u64,
    pub workers: u64,
    /// The delegated cgroup the run divides into one pen per worker.
    pub cgroup: PathBuf,
    /// Each pen's memory limit in bytes and its process limit.
    pub memory: u64,
    pub processes: u64,
}

/// `fuzz.json`: what a root carries from one run to the next.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Record {
    /// The number the next run takes.
    next: u64,
    /// The merges in a row, each of a run that reached its deadline, that
    /// left the corpus in place.
    failed_merges: u64,
    /// The last run started, whose failure files the next start takes in.
    last: Option<Last>,
    /// Absent, like `alarm`, from a record written before any control.
    #[serde(default)]
    control: Controls,
    /// A run's control was missed. It stays set.
    #[serde(default)]
    alarm: bool,
    /// Each key's failures, [`super::OTHER`] among them.
    #[serde(default)]
    keys: BTreeMap<String, u64>,
}

/// The state the record lock of a [`Session`] guards.
struct Filing {
    /// `fuzz.json` as the run last stored it.
    record: Record,
    /// Each base and key whose first failure a thread stages outside
    /// the lock. A thread filing the same `(base, key)` before the key's
    /// directory exists waits on [`Session::stored`] until the entry
    /// leaves `storing`. Each pending key whose base is the fuzz root
    /// counts toward the key bound.
    storing: BTreeSet<(PathBuf, String)>,
}

/// A started run's number and its archive's build digest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Last {
    run: u64,
    build: Text,
}

/// The runs whose planted control was caught and missed.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Controls {
    caught: u64,
    missed: u64,
}

/// The archived worker as a run starts it.
struct Worker {
    /// The archived executable and the variables the approved command sets.
    program: OsString,
    environment: Vec<(OsString, Option<OsString>)>,
    /// This executable, whose `gate` subcommand starts each worker once it
    /// is in its pen.
    gate: PathBuf,
    /// The archive's build digest and its build record's provenance.
    build: Text,
    provenance: Provenance,
}

/// One process the monitor watches: the control worker, a fuzz worker, a
/// merge or a rerun.
struct Job {
    arguments: Vec<OsString>,
    log: PathBuf,
    limit: Instant,
}

struct Running {
    child: Child,
    pen: Arc<Pen>,
    /// The file its output goes to.
    log: PathBuf,
    /// When the monitor kills the pen: the job's limit, or the time a stop
    /// came plus [`Bounds::grace`] when that is earlier.
    limit: Instant,
    /// The bound the monitor killed the pen at; `time` covers a kill at
    /// the job's limit and one a grace period after a stop.
    killed: Option<&'static str>,
    stopped: bool,
}

type Slot = Mutex<Option<Running>>;

/// How a watched process ended.
#[derive(Debug)]
struct Ended {
    /// Its exit status; `None` when the wait for it failed.
    status: Option<ExitStatus>,
    killed: Option<&'static str>,
    /// Whether the pen's out-of-memory kill count rose while the process
    /// ran.
    out_of_memory: bool,
    counts: Option<String>,
    /// The file name of the process's output. `run.json` records it for
    /// each worker and the merge, whose output lies in the run's
    /// directory. Removing the `.stderr` suffix yields the artifact
    /// directory name.
    output: String,
    /// The monitor sent it the run's stop, so its end is no failure.
    stopped: bool,
    /// How intake filed its failure.
    filed: Option<Filed>,
}

impl Ended {
    /// Whether the process failed: it ended otherwise than with exit 0,
    /// for a cause other than the run's stop.
    fn failed(&self) -> bool {
        !self.stopped && !self.status.is_some_and(|status| status.success())
    }

    fn value(&self) -> Value {
        use std::os::unix::process::ExitStatusExt;
        json!({
            "code": self.status.and_then(|status| status.code()),
            "signal": self.status.and_then(|status| status.signal()),
            "killed": self.killed,
            "out_of_memory": self.out_of_memory,
            "counts": self.counts,
            "output": self.output,
            "key": self.filed.as_ref().map(|filed| &filed.key),
            "rerun": self.filed.as_ref().and_then(|filed| filed.rerun),
        })
    }
}

/// What a run did once its control ended.
struct Ran {
    /// What ended the run before its workers and its merge ended, as
    /// [`ending`] names it, else the cause [`Session::stop`] names, else
    /// `deadline`.
    ending: &'static str,
    /// The end of each fuzz worker that started, replacements included;
    /// empty for a run whose control was missed or interrupted.
    workers: Vec<Ended>,
    /// The corpus's files once the workers ended, or once the control
    /// ended for a run that started none.
    after: u64,
    /// The merge, `None` for a run that started none.
    merge: Option<Merged>,
}

/// How a run's planted control ended.
#[derive(Debug, PartialEq, Eq)]
enum Control {
    /// Its worker ended on its own and [`intake::caught`] accepted it.
    Caught,
    /// It ran to its end with any other result, or the run killed its
    /// worker at a bound.
    Missed,
    /// A stop kept it from starting, or ended its worker or its rerun.
    Interrupted,
}

struct Merged {
    ended: Ended,
    /// Why the run kept its corpus; `None` for an adopted merge.
    cause: Option<String>,
    files: u64,
    /// The attempts its `MERGE-OUTER` line reports: one more than the
    /// inner processes a failing input ended.
    attempts: Option<u64>,
}

/// One run of a root, from its number's claim to its records.
struct Session<'a> {
    plan: &'a Plan,
    worker: &'a Worker,
    number: u64,
    directory: PathBuf,
    /// The record lock over `fuzz.json` and the keys being staged.
    filing: Mutex<Filing>,
    /// Wakes the intakes waiting on a key once the thread staging the
    /// key's first failure has published it or returned an error.
    stored: Condvar,
    /// The corpus's files when the run takes its number, once a killed
    /// run's files are filed.
    before: AtomicU64,
    /// When the run's seed writer returned, in seconds since the epoch.
    started: AtomicU64,
    bounds: Bounds,
    limits: Limits,
    /// Why the run stops, set once: `signal`, `failure` of a thread,
    /// `failed workers` or `key table full`. Once it is set
    /// no process starts, and the monitor sends SIGTERM to each one.
    stop: OnceLock<&'static str>,
    /// The failed workers, and the next replacement's directory number.
    failed: AtomicU64,
    next: AtomicU64,
}

/// Accepts a root and an archive path whose bytes are all in
/// `A-Za-z0-9/._=,-`, the bytes a merge's shell line passes as they are.
///
/// # Errors
///
/// [`Error::Rejected`] naming a path with another byte, or an empty one.
pub(in crate::campaign) fn accepted(root: &Path, archive: &Path) -> Result<(), Error> {
    for (name, path) in [("root", root), ("archive", archive)] {
        let bytes = path.as_os_str().as_encoded_bytes();
        let plain = bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._=,-".contains(byte));
        if bytes.is_empty() || !plain {
            return Err(Error::Rejected(format!(
                "the fuzz {name} {} must be nonempty and hold only the bytes A-Za-z0-9/._=,-, \
                 since the merge passes it to a shell unquoted",
                path.display()
            )));
        }
    }
    Ok(())
}

fn seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Leaves `root` holding `corpus/` alone of the corpus directories. A
/// kill between the swap's two renames leaves `corpus.old` in place of
/// `corpus/`, and it is renamed back; a kill after both leaves
/// `corpus.old` beside `corpus/`, and it is removed, as is the
/// `corpus.new` a merge or a cut swap left. A new root gets an empty
/// `corpus/`. The removals run only after `create_dirs` succeeds for it.
fn recovered(root: &Path) -> io::Result<()> {
    let (corpus, old) = (root.join("corpus"), root.join("corpus.old"));
    if !present_host(&corpus)? && present_host(&old)? {
        rename_host(&old, &corpus)?;
    }
    crate::store::create_dirs(&corpus)?;
    remove_tree(&root.join("corpus.new"))?;
    remove_tree(&old)
}

/// Replaces `corpus/` under `root` with `corpus.new`. The swap syncs the
/// filesystem that holds `corpus.new` before either rename, so the merged
/// files are durable before a rename publishes them, and retains
/// `corpus.old` until the sync of the root directory after both renames
/// succeeds.
fn swapped(root: &Path) -> io::Result<()> {
    let (corpus, old, new) = (
        root.join("corpus"),
        root.join("corpus.old"),
        root.join("corpus.new"),
    );
    crate::store::sync_filesystem_host(&new)?;
    rename_host(&corpus, &old)?;
    rename_host(&new, &corpus)?;
    crate::store::sync_parent(&corpus)?;
    remove_tree(&old)
}

/// Keeps the [`RUNS_KEPT`] run directories under `runs` with the highest
/// numbers and removes the other run directories. A run directory is a
/// subdirectory whose name parses as a run number.
fn pruned(runs: &Path) -> io::Result<()> {
    let mut numbers = Vec::new();
    for name in crate::store::subdirectories(runs)? {
        let name = name.to_str().unwrap_or("");
        if let Some(number) = name.parse::<u64>().ok().filter(|n| n.to_string() == name) {
            numbers.push(number);
        }
    }
    numbers.sort_unstable();
    let kept = numbers.len().saturating_sub(RUNS_KEPT);
    numbers[..kept]
        .iter()
        .try_for_each(|number| remove_tree(&runs.join(number.to_string())))
}

/// The record `fuzz.json` holds under `root`, or `None` without the file.
///
/// # Errors
///
/// [`Error::Unreadable`] for a file that cannot be read or holds more
/// than [`RECORD_BOUND`] bytes, and
/// [`Error::Held`] for bytes that do not parse as a record.
fn read(root: &Path) -> Result<Option<Record>, Error> {
    let Some(bytes) = crate::store::read_host(&root.join("fuzz.json"), RECORD_BOUND)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| Error::Held(format!("fuzz.json: {error}")))
}

fn store(root: &Path, record: &Record) -> io::Result<()> {
    let bytes = serde_json::to_vec(record).expect("the record encodes");
    crate::store::replace_host(&root.join("fuzz.json"), &bytes)
}

/// The last [`TAIL`] bytes of the file `log`; `None` for one that cannot
/// be read.
fn tail(log: &Path) -> Option<Vec<u8>> {
    let opened = open_host(log).ok()?;
    let start = opened.len().saturating_sub(TAIL);
    let mut bytes = vec![0; usize::try_from(opened.len() - start).ok()?];
    opened.read_exact_at(&mut bytes, start).ok()?;
    Some(bytes)
}

/// The first [`START`] bytes of the file `log`, read as text.
fn opening(log: &Path) -> io::Result<String> {
    let opened = open_host(log).map_err(io::Error::other)?;
    let mut start = vec![0; opened.len().min(START) as usize];
    opened.read_exact_at(&mut start, 0)?;
    Ok(String::from_utf8_lossy(&start).into_owned())
}

/// Whether the first [`START`] bytes of the file `log` hold [`COUNTERS`].
fn reports_counters(log: &Path) -> io::Result<bool> {
    Ok(opening(log)?.contains(COUNTERS))
}

/// A gate failure before worker startup holds the run.
fn unstarted(log: &Path, ended: &Ended) -> io::Result<Option<Error>> {
    let code = ended.status.and_then(|status| status.code());
    if !crate::exit::gate_code(code) {
        return Ok(None);
    }
    let text = opening(log)?;
    let line = text.lines().next().unwrap_or_default();
    Ok(crate::exit::gate_failed(code, line).then(|| {
        Error::Held(format!(
            "the gate failed before it started the worker; {} reads: {line}",
            log.display()
        ))
    }))
}

/// The refusal of a control worker that ended as `ended` and whose
/// output `log` [`reports_counters`] found no line in. It states how the
/// worker ended: its status, a bound the run killed its pen at, and an
/// out-of-memory kill the pen counted.
fn uncounted(log: &Path, ended: &Ended) -> Error {
    let status = ended
        .status
        .map_or("no status".into(), |status| status.to_string());
    let killed = ended.killed.map_or(String::new(), |bound| {
        format!("; the run killed its pen at the {bound} bound")
    });
    let memory = if ended.out_of_memory {
        "; the pen counted an out-of-memory kill"
    } else {
        ""
    };
    Error::Rejected(format!(
        "the first {START} bytes of the control worker's output {} hold no `{COUNTERS}` line, \
         which a worker built with libFuzzer's coverage counters prints at its start; the \
         worker ended with {status}{killed}{memory}",
        log.display()
    ))
}

/// The ending of a run that starts no fuzz worker: [`MISSED`] for a
/// missed control, whatever `stop` holds, else the cause `stop` names.
/// `None` for a caught control with no stop, after which the workers
/// start.
///
/// # Errors
///
/// [`Error::Held`] for an interrupted control with no stop, a pair
/// [`Session::controlled`] never returns.
fn ending(control: &Control, stop: Option<&'static str>) -> Result<Option<&'static str>, Error> {
    match (control, stop) {
        (Control::Missed, _) => Ok(Some(MISSED)),
        (Control::Caught, None) => Ok(None),
        (Control::Caught | Control::Interrupted, Some(stop)) => Ok(Some(stop)),
        (Control::Interrupted, None) => Err(Error::Held(
            "the control was interrupted with no stop set".into(),
        )),
    }
}

/// The last counts line of the `campaign` target among the last [`TAIL`]
/// bytes of the file `log`.
fn counts(log: &Path) -> Option<String> {
    String::from_utf8_lossy(&tail(log)?)
        .lines()
        .rev()
        .find(|line| line.starts_with(COUNTS))
        .map(str::to_owned)
}

/// The worker's `--fuzz` form for `target` with artifact directory
/// `artifacts` and the libFuzzer arguments `libfuzzer`.
fn form(
    target: &str,
    artifacts: &Path,
    libfuzzer: impl IntoIterator<Item = OsString>,
) -> Vec<OsString> {
    let ours = ["--fuzz", target, "--artifacts"].map(OsString::from);
    ours.into_iter()
        .chain([artifacts.into(), "--".into()])
        .chain(libfuzzer)
        .collect()
}

/// The `--fuzz` form of a `campaign` worker or merge: [`LIMITS`], the
/// `-rss_limit_mb` [`rss_limit_mb`] derives from `memory`, the pen's
/// memory limit in bytes, and the artifact prefix of `artifacts`, then
/// the arguments `libfuzzer`.
fn bounded(
    artifacts: &Path,
    memory: u64,
    libfuzzer: impl IntoIterator<Item = OsString>,
) -> Vec<OsString> {
    let rss = format!("-rss_limit_mb={}", rss_limit_mb(memory)).into();
    let prefix = format!("-artifact_prefix={}/", artifacts.display()).into();
    let limits = LIMITS.map(OsString::from).into_iter().chain([rss, prefix]);
    form("campaign", artifacts, limits.chain(libfuzzer))
}

/// Probes whether the worker accepts `-merge=1`. `-help=1` makes libFuzzer
/// exit 0 before merge processing begins.
///
/// # Errors
///
/// `merging` returns [`Error::Rejected`] with a corpus merge diagnostic if
/// the probe terminates unsuccessfully, and [`Error::Held`] if it cannot
/// run, outlives [`SEEDS_WAIT`], or prints past the archive's output bound
/// on either stream.
fn merging(worker: &Worker, root: &Path, memory: u64) -> Result<(), Error> {
    let libfuzzer = [
        "-merge=1".into(),
        format!("-merge_control_file={}/merge.txt", root.display()).into(),
        "-help=1".into(),
    ];
    let mut command = archived(worker.program.as_os_str(), &worker.environment);
    command.args(bounded(root, memory, libfuzzer));
    crate::sys::working_directory(&mut command, root);
    crate::archive::output(&mut command, SEEDS_WAIT)
        .map(drop)
        .map_err(|failure| match failure {
            crate::archive::Unsuccessful::Ended(_) => Error::Rejected(format!(
                "the archived worker refuses a corpus merge, which every run ends with: {failure}"
            )),
            crate::archive::Unsuccessful::Failed(_) => {
                Error::Held(format!("the worker's corpus merge probe: {failure}"))
            }
        })
}

/// Opens the run `plan` names on a root the caller holds, before it
/// takes its number: recovers a cut swap, checks the corpus bound, and
/// makes the records agree with the failure directories.
///
/// # Errors
///
/// [`Error::Held`] for a corpus past [`crate::scan_bound`] files, a failed
/// listing of the corpus and a root whose key table is full, which keeps
/// every failure file and run directory.
/// When `record.alarm` is set, `opened` returns [`Error::Held`] to
/// preserve the missed control's evidence in `control/`.
fn opened<'a>(plan: &'a Plan, worker: &'a Worker, limits: Limits) -> Result<Session<'a>, Error> {
    recovered(&plan.root).map_err(held)?;
    let before = regular_files(&plan.root.join("corpus")).map_err(held)?;
    let bound = crate::scan_bound() as u64;
    if before > bound {
        return Err(Error::Held(format!(
            "the corpus holds {before} files, past the {bound} a run starts from; merge it by \
             hand first"
        )));
    }
    let mut record = read(&plan.root)?.unwrap_or_default();
    intake::repaired(&plan.root, &mut record.keys)?;
    store(&plan.root, &record).map_err(held)?;
    if record.alarm {
        return Err(Error::Held(
            "the root's planted control was missed; keep the root as the record, with the \
             miss under control/, and start a new root with its corpus"
                .into(),
        ));
    }
    if intake::known(&plan.root, super::OTHER)? {
        return Err(Error::Held(format!(
            "the root holds a failure past its {} keys; keep it as the record and start a \
             new root with its corpus",
            super::KEYS
        )));
    }
    Ok(Session {
        plan,
        worker,
        number: record.next,
        directory: plan.root.join("runs").join(record.next.to_string()),
        filing: Mutex::new(Filing {
            record,
            storing: BTreeSet::new(),
        }),
        stored: Condvar::new(),
        before: AtomicU64::new(before),
        started: AtomicU64::new(seconds_now()),
        bounds: BOUNDS,
        limits,
        stop: OnceLock::new(),
        failed: AtomicU64::new(0),
        next: AtomicU64::new(plan.workers),
    })
}

impl Session<'_> {
    /// Files what a killed run left, with reruns in `pen` when one is
    /// given, then takes the run's number: stores the advanced number
    /// with this run and its build, creates the run's directory, prunes
    /// the run directories and writes its seeds. The intake precedes the
    /// pruning, and the number is stored before its directory exists, so
    /// a run killed after this point keeps its number to itself.
    fn advance(&self, pen: Option<(&Arc<Pen>, &Slot)>) -> Result<(), Error> {
        self.leftover(pen)?;
        let corpus = regular_files(&self.plan.root.join("corpus")).map_err(held)?;
        self.before.store(corpus, Ordering::Relaxed);
        let mut filing = self.filing.lock().expect("no thread panics holding it");
        let record = &mut filing.record;
        record.next = self
            .number
            .checked_add(1)
            .ok_or_else(|| Error::Held("fuzz.json holds the last run number".into()))?;
        record.last = Some(Last {
            run: self.number,
            build: self.worker.build.clone(),
        });
        store(&self.plan.root, record).map_err(held)?;
        let runs = self.plan.root.join("runs");
        let seeds = self.directory.join("seeds");
        crate::store::create_dirs(&runs)
            .and_then(|()| crate::store::create_dir(&self.directory))
            .and_then(|()| pruned(&runs))
            .and_then(|()| crate::store::create_dir(&seeds))
            .map_err(held)?;
        let mut command = archived(self.worker.program.as_os_str(), &self.worker.environment);
        command.arg("--seeds").arg("campaign").arg(&seeds);
        crate::sys::working_directory(&mut command, &self.directory);
        crate::archive::output(&mut command, SEEDS_WAIT)
            .map_err(|failure| Error::Held(format!("the worker's seeds: {failure}")))?;
        self.started.store(seconds_now(), Ordering::Relaxed);
        Ok(())
    }

    /// Takes a pending SIGINT or SIGTERM, waiting up to `wait`, and sets
    /// `stop` when one came or the wait failed. The calling thread must
    /// block both signals, as [`crate::sys::block_interruptions`] does.
    fn interrupted(&self, wait: Duration) -> Result<(), Error> {
        let taken = crate::sys::interruption(wait);
        if !matches!(taken, Ok(None)) {
            let _ = self.stop.set("signal");
        }
        taken.map(drop).map_err(held)
    }

    /// The run of the failures this run's processes leave.
    fn origin(&self) -> Origin<'_> {
        Origin {
            run: self.number,
            build: &self.worker.build,
            provenance: Some(&self.worker.provenance),
        }
    }

    /// Runs `work` for thread `index` in a new pen under `cgroup` and
    /// removes the pen.
    fn penned<T>(
        &self,
        index: usize,
        cgroup: &Root,
        slot: &Slot,
        work: &(impl Fn(usize, &Arc<Pen>, &Slot) -> Result<T, Error> + Sync),
    ) -> Result<T, Error> {
        let pen = Arc::new(Pen::create(cgroup, index, self.limits).map_err(held)?);
        let done = work(index, &pen, slot);
        let removed = Arc::into_inner(pen)
            .expect("the thread holds the last reference to its pen")
            .remove()
            .map_err(held);
        done.and_then(|done| removed.map(|()| done))
    }

    /// Starts `job`'s worker behind the gate inside `pen`, places it in
    /// `slot` for the monitor and waits for it to exit. The slot lock is
    /// held for each poll alone, and the worker leaves the slot once it is
    /// reaped, so the monitor signals the worker itself and never a later
    /// process with its ID. A stop that has come by the call's start
    /// returns `None` with nothing created. One that comes before the go
    /// byte withholds the byte, so the gate ends without starting the
    /// job's process, and the call returns `None` once the gate is reaped.
    /// The pen's out-of-memory count is read at every process's end, so a
    /// kill belongs to the process it ended.
    ///
    /// # Errors
    ///
    /// `waited` returns [`Error::Held`] if output file or gate creation
    /// fails, the pen refuses the gate, the pen cannot be emptied or
    /// read, or a released gate fails before worker startup
    /// ([`unstarted`]). The gate failure takes precedence over the stop
    /// recorded in `stopped`.
    fn waited(&self, pen: &Arc<Pen>, job: &Job, slot: &Slot) -> Result<Option<Ended>, Error> {
        const WAIT: Duration = Duration::from_millis(10);
        if self.stop.get().is_some() {
            return Ok(None);
        }
        let log = crate::store::create_host(&job.log).map_err(held)?;
        let mut command = archived(self.worker.gate.as_os_str(), &self.worker.environment);
        command
            .arg("gate")
            .arg("--")
            .arg(&self.worker.program)
            .args(&job.arguments)
            .stdin(Stdio::piped())
            .stdout(log.try_clone().map_err(held)?)
            .stderr(log);
        // The directory of its output file exists and lies in the root.
        let directory = job.log.parent().unwrap_or(&self.plan.root);
        crate::sys::working_directory(&mut command, directory);
        crate::sys::lead(&mut command);
        let mut child = command.spawn().map_err(held)?;
        if let Err(error) = pen.admit(&child) {
            end(&child);
            let _ = child.wait();
            return Err(held(error));
        }
        let mut go = child.stdin.take().expect("the gate's stdin is piped");
        *slot.lock().expect("the slot lock is clean") = Some(Running {
            child,
            pen: Arc::clone(pen),
            log: job.log.clone(),
            limit: job.limit,
            killed: None,
            stopped: false,
        });
        // Creating the output file and starting the gate take long enough
        // for a stop to come, so the byte is sent only while none has.
        let released = self.stop.get().is_none();
        if released {
            let _ = go.write_all(b"G");
        }
        drop(go);
        let (status, killed, stopped) = loop {
            let mut held_slot = slot.lock().expect("the slot lock is clean");
            let running = held_slot.as_mut().expect("the worker is in its slot");
            let exited = running.child.try_wait();
            if !matches!(exited, Ok(None)) {
                let ended = (exited.ok().flatten(), running.killed, running.stopped);
                *held_slot = None;
                break ended;
            }
            drop(held_slot);
            std::thread::sleep(WAIT);
        };
        pen.empty().map_err(held)?;
        let ended = Ended {
            status,
            killed,
            out_of_memory: pen.out_of_memory().map_err(held)?,
            counts: counts(&job.log),
            output: job
                .log
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
            stopped,
            filed: None,
        };
        // An unreleased gate can report the same exit status as a failed
        // gate.
        if !released {
            return Ok(None);
        }
        match unstarted(&job.log, &ended).map_err(held)? {
            Some(refusal) => Err(refusal),
            None => Ok(Some(ended)),
        }
    }

    /// Runs `work` on `threads` threads, each in its own pen under
    /// `cgroup`, and returns what each returned, in order. Until every
    /// thread has ended the monitor takes SIGINT and SIGTERM, sends
    /// SIGTERM to each running process once a stop came, and kills the
    /// pen of a process past its limit or past [`Bounds::output`].
    ///
    /// # Errors
    ///
    /// A thread the host does not start, a failed signal wait, or else the
    /// first thread's failure; each stops the run.
    fn watched<T: Send>(
        &self,
        cgroup: &Root,
        threads: u64,
        work: impl Fn(usize, &Arc<Pen>, &Slot) -> Result<T, Error> + Sync,
    ) -> Result<Vec<T>, Error> {
        let mut failed = self.interrupted(Duration::ZERO).err();
        let slots: Vec<Slot> = (0..threads).map(|_| Mutex::new(None)).collect();
        let work = &work;
        let mut ended = Vec::new();
        std::thread::scope(|scope| {
            let mut threads = Vec::new();
            for (index, slot) in slots.iter().enumerate() {
                let started = std::thread::Builder::new().spawn_scoped(scope, move || {
                    let ended = self.penned(index, cgroup, slot, work);
                    if ended.is_err() {
                        let _ = self.stop.set("failure");
                    }
                    ended
                });
                match started {
                    Ok(thread) => threads.push(thread),
                    Err(error) => {
                        failed.get_or_insert(Error::Held(format!(
                            "a fuzz thread did not start: {error}"
                        )));
                        let _ = self.stop.set("failure");
                        break;
                    }
                }
            }
            while threads.iter().any(|thread| !thread.is_finished()) {
                if let Err(error) = self.interrupted(POLL) {
                    failed.get_or_insert(error);
                    // A failed wait returns at once.
                    std::thread::sleep(POLL);
                }
                let stop = self.stop.get().is_some();
                for slot in &slots {
                    let mut slot = slot.lock().expect("the slot lock is clean");
                    let Some(running) = slot.as_mut() else {
                        continue;
                    };
                    let now = Instant::now();
                    if stop && !running.stopped && running.killed.is_none() {
                        running.limit = running.limit.min(now + self.bounds.grace);
                        let sent = crate::sys::terminate_child(&mut running.child);
                        running.stopped = !matches!(sent, Ok(false));
                    }
                    let output = open_host(&running.log).map_or(u64::MAX, |opened| opened.len());
                    if let Some(bound) = self.bounds.passed(now, running.limit, output) {
                        // The kill repeats on each pass until the thread
                        // reaps the worker, so a failed kill is tried
                        // again.
                        if !matches!(crate::sys::exited(running.child.id()), Ok(true)) {
                            running.killed.get_or_insert(bound);
                        }
                        if running.pen.kill().is_err() {
                            end(&running.child);
                        }
                    }
                }
            }
            for thread in threads {
                match thread.join().expect("a fuzz thread returns") {
                    Ok(one) => ended.push(one),
                    Err(error) => {
                        failed.get_or_insert(error);
                    }
                }
            }
        });
        failed.map_or(Ok(ended), Err)
    }

    /// Runs the planted control: empties `control/`, runs the `planted`
    /// target on the run's `upload` seed, and files its failure with
    /// `control/` as the base, so the root's findings stay as they are.
    /// A stop already set, or a signal already pending, at the call's
    /// start leaves the last control's `control/` in place. A stop that
    /// comes after that check and before the worker's process starts is
    /// [`Control::Interrupted`] with `control/` holding what this call
    /// created by then. A control that ran to its end is counted by
    /// [`Session::judged`], whatever stop came after it; one a stop
    /// ended, or whose rerun a stop cut, is [`Control::Interrupted`]. A
    /// worker the run killed at its time or output bound is missed
    /// whatever it kept, and intake files its failure under `control/` as
    /// it files any other.
    ///
    /// # Errors
    ///
    /// [`Error::Rejected`], with the counts unchanged, for a control
    /// worker that ran to its end, passing or failing, and whose output
    /// holds no [`COUNTERS`] line in its first [`START`] bytes.
    /// [`Error::Held`] for a failed signal wait, a
    /// failed removal or write under `control/` and an output file that
    /// cannot be read.
    /// Each error of [`Session::watched`], [`Session::waited`],
    /// [`Session::intake`] and [`Session::judged`].
    fn controlled(&self, cgroup: &Root) -> Result<Control, Error> {
        enum Worked {
            Stopped,
            Passed,
            /// The failure as intake filed it, and whether the run killed
            /// the worker at a bound.
            Failed(Filed, bool),
        }
        self.interrupted(Duration::ZERO)?;
        if self.stop.get().is_some() {
            return Ok(Control::Interrupted);
        }
        let base = self.plan.root.join("control");
        let artifacts = base.join("w");
        remove_tree(&base)
            .and_then(|()| crate::store::create_dirs(&artifacts))
            .map_err(held)?;
        let seed = self.directory.join("seeds/upload.input");
        let job = Job {
            arguments: form("planted", &artifacts, [seed.into()]),
            log: base.join("w.stderr"),
            limit: Instant::now() + RERUN,
        };
        let worked = self.watched(cgroup, 1, |_, pen, slot| {
            let Some(ended) = self.waited(pen, &job, slot)?.filter(|ended| !ended.stopped) else {
                return Ok(Worked::Stopped);
            };
            if !reports_counters(&job.log).map_err(held)? {
                return Err(uncounted(&job.log, &ended));
            }
            if !ended.failed() {
                return Ok(Worked::Passed);
            }
            let failure = Failure::of("planted", &artifacts, &job, &ended);
            let filed = self.intake(&base, &self.origin(), &failure, Some((pen, slot)))?;
            Ok(Worked::Failed(filed, ended.killed.is_some()))
        })?;
        match worked.into_iter().next() {
            Some(Worked::Passed) => self.judged(&base, None),
            Some(Worked::Failed(filed, killed)) if !filed.cut => {
                self.judged(&base, (!killed).then_some(&filed))
            }
            Some(Worked::Stopped | Worked::Failed(..)) | None => Ok(Control::Interrupted),
        }
    }

    /// Counts a control that ran to its end and stores the record:
    /// `filed` is its failure as intake filed it under `base`, `None`
    /// for a worker that exited 0 and for one the run killed at a bound.
    /// A control [`intake::caught`] accepts adds to the caught controls.
    /// Every other one adds to the missed controls and sets the alarm.
    /// Each count stays at `u64::MAX` once it is there.
    ///
    /// # Errors
    ///
    /// With the counts and the alarm unchanged, each error of
    /// [`intake::caught`]. [`Error::Held`] for a failed write of
    /// `fuzz.json`.
    fn judged(&self, base: &Path, filed: Option<&Filed>) -> Result<Control, Error> {
        let caught = match filed {
            Some(filed) => intake::caught(base, filed)?,
            None => false,
        };
        let mut filing = self.filing.lock().expect("no thread panics holding it");
        let record = &mut filing.record;
        let control = &mut record.control;
        if caught {
            control.caught = control.caught.saturating_add(1);
        } else {
            control.missed = control.missed.saturating_add(1);
            record.alarm = true;
        }
        store(&self.plan.root, record).map_err(held)?;
        Ok(if caught {
            Control::Caught
        } else {
            Control::Missed
        })
    }

    /// Runs the control, then the workers and the merge when
    /// [`ending`] names no ending for the control's result. Any other
    /// run starts no fuzz worker and no merge.
    ///
    /// # Errors
    ///
    /// As [`Session::controlled`], [`ending`] and [`Session::fuzzed`],
    /// and a corpus that cannot be counted.
    fn ran(&self, cgroup: &Root) -> Result<Ran, Error> {
        let control = self.controlled(cgroup)?;
        let Some(ending) = ending(&control, self.stop.get().copied())? else {
            return self.fuzzed(cgroup);
        };
        Ok(Ran {
            ending,
            workers: Vec::new(),
            after: regular_files(&self.plan.root.join("corpus")).map_err(held)?,
            merge: None,
        })
    }

    /// Thread `index`'s workers in `pen`: one worker, then a replacement
    /// for the time left after each worker that fails, until `deadline`
    /// or a stop. A failed worker counts when it ends and is then filed.
    /// A thread starts no worker once it reads that [`FAILED`] have
    /// failed, and the filing of the [`FAILED`]th stops the run, so its
    /// own rerun runs first; a worker already running or being started
    /// that fails before the stop counts too.
    fn worked(
        &self,
        index: usize,
        pen: &Arc<Pen>,
        slot: &Slot,
        deadline: Instant,
    ) -> Result<Vec<Ended>, Error> {
        let mut ended = Vec::new();
        let mut number = index as u64;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let seconds = left.as_millis().div_ceil(1000);
            let spent = self.failed.load(Ordering::Relaxed) >= FAILED;
            if seconds == 0 || spent || self.stop.get().is_some() {
                break;
            }
            let artifacts = self.directory.join(format!("w{number}"));
            crate::store::create_dir(&artifacts).map_err(held)?;
            let libfuzzer = [
                format!("-max_total_time={seconds}").into(),
                self.plan.root.join("corpus").into(),
                self.directory.join("seeds").into(),
            ];
            let job = Job {
                arguments: bounded(&artifacts, self.limits.memory, libfuzzer),
                log: self.directory.join(format!("w{number}.stderr")),
                limit: deadline + self.bounds.grace,
            };
            let Some(mut one) = self.waited(pen, &job, slot)? else {
                break;
            };
            let failed = one.failed();
            if failed {
                let count = self.failed.fetch_add(1, Ordering::Relaxed) + 1;
                let failure = Failure::of("campaign", &artifacts, &job, &one);
                let filed =
                    self.intake(&self.plan.root, &self.origin(), &failure, Some((pen, slot)))?;
                one.filed = Some(filed);
                if count >= FAILED {
                    let _ = self.stop.set("failed workers");
                }
            }
            ended.push(one);
            if !failed {
                break;
            }
            number = self.next.fetch_add(1, Ordering::Relaxed);
        }
        Ok(ended)
    }

    /// Runs the workers under `cgroup` until the deadline or a stop, then
    /// the merge when the run reached its deadline.
    ///
    /// # Errors
    ///
    /// As [`Session::watched`] and [`Session::merged`], and a failed write
    /// or listing under the root.
    fn fuzzed(&self, cgroup: &Root) -> Result<Ran, Error> {
        let deadline = Instant::now() + Duration::from_secs(self.plan.seconds);
        let workers = self.watched(cgroup, self.plan.workers, |index, pen, slot| {
            self.worked(index, pen, slot, deadline)
        })?;
        let after = regular_files(&self.plan.root.join("corpus")).map_err(held)?;
        let merge = match self.stop.get() {
            Some(_) => None,
            None => self.merged(cgroup)?,
        };
        Ok(Ran {
            ending: self.stop.get().copied().unwrap_or("deadline"),
            workers: workers.into_iter().flatten().collect(),
            after,
            merge,
        })
    }

    /// Merges `corpus/` and the run's seeds into a new `corpus.new` in a
    /// pen under `cgroup`, and swaps it in when the merge, with no stop and
    /// no kill, exited 0 and wrote a file. Returns the merge's end with the cause of a merge
    /// the run left unadopted, or `None` once a stop came first.
    ///
    /// # Errors
    ///
    /// As [`Session::watched`], and a failed write, swap, removal or
    /// listing under the root. A `corpus.new` listing error holds the run when its kind
    /// differs from `io::ErrorKind::InvalidData`.
    fn merged(&self, cgroup: &Root) -> Result<Option<Merged>, Error> {
        let root = &self.plan.root;
        let new = root.join("corpus.new");
        let artifacts = self.directory.join("merge");
        remove_tree(&new)
            .and_then(|()| crate::store::create_dir(&new))
            .and_then(|()| crate::store::create_dir(&artifacts))
            .map_err(held)?;
        let libfuzzer = [
            "-merge=1".into(),
            format!("-merge_control_file={}/merge.txt", self.directory.display()).into(),
            new.clone().into(),
            root.join("corpus").into(),
            self.directory.join("seeds").into(),
        ];
        let job = Job {
            arguments: bounded(&artifacts, self.limits.memory, libfuzzer),
            log: self.directory.join("merge.stderr"),
            limit: Instant::now() + self.bounds.merge,
        };
        // A merge passes over an inner process a failing input ended, so
        // its artifact directory is filed whatever the merge's exit, once
        // for each failing input it holds.
        let ended = self.watched(cgroup, 1, |_, pen, slot| {
            let Some(mut ended) = self.waited(pen, &job, slot)? else {
                return Ok(None);
            };
            let failure = Failure::of("campaign", &artifacts, &job, &ended);
            ended.filed = self.drained(&self.origin(), &failure, Some((pen, slot)))?;
            Ok(Some(ended))
        })?;
        let Some(ended) = ended.into_iter().flatten().next() else {
            remove_tree(&new).map_err(held)?;
            return Ok(None);
        };
        let cause = match (ended.killed, ended.status) {
            _ if self.stop.get().is_some() => Some("a stop came during the merge".to_owned()),
            (Some(bound), _) => Some(format!("the merge was killed at its {bound} bound")),
            (None, None) => Some("the wait for the merge failed".to_owned()),
            (None, Some(status)) if !status.success() => {
                Some(format!("the merge ended with {status}"))
            }
            (None, Some(_)) => match regular_files(&new) {
                Ok(files) if files > 0 => None,
                Err(error) if error.kind() != io::ErrorKind::InvalidData => {
                    return Err(held(error));
                }
                _ => Some("the merge left no regular file alone in corpus.new".to_owned()),
            },
        };
        match cause {
            None => swapped(root),
            Some(_) => remove_tree(&new),
        }
        .map_err(held)?;
        let files = regular_files(&root.join("corpus")).map_err(held)?;
        let log = String::from_utf8_lossy(&tail(&job.log).unwrap_or_default()).into_owned();
        let attempts = log.lines().rev().find_map(|line| {
            let count = line.split_once("MERGE-OUTER: successful in ")?.1;
            count.split(' ').next()?.parse().ok()
        });
        Ok(Some(Merged {
            ended,
            cause,
            files,
            attempts,
        }))
    }

    /// Writes `run.json` for `ran` and `finished`, the closing
    /// verification of the archive, then replaces `fuzz.json` with the
    /// count of consecutive unadopted merges. Returns the run's record.
    ///
    /// # Errors
    ///
    /// [`Error::Held`] for a failed write, and for a failed closing
    /// verification once both files are written.
    fn closed(self, ran: &Ran, finished: Result<(), String>) -> Result<Value, Error> {
        let filing = self.filing.into_inner();
        let mut record = filing.expect("no thread panics holding it").record;
        // A merge a stop ended says nothing of the corpus, so it leaves the
        // count of consecutive merges that kept the corpus as it was.
        match &ran.merge {
            Some(merged) if merged.cause.is_none() => record.failed_merges = 0,
            Some(_) if ran.ending == "deadline" => {
                record.failed_merges = record.failed_merges.saturating_add(1);
            }
            _ => {}
        }
        let workers: Vec<Value> = ran.workers.iter().map(Ended::value).collect();
        let value = json!({
            "run": self.number,
            "build": self.worker.build.as_str(),
            "started": self.started.into_inner(),
            "ended": seconds_now(),
            "seconds": self.plan.seconds,
            "ending": ran.ending,
            "workers": workers,
            "failed": self.failed.into_inner(),
            "corpus": {
                "before": self.before.into_inner(),
                "after": ran.after,
                "merged": ran.merge.as_ref().map(|merged| merged.files),
            },
            "merge": ran.merge.as_ref().map(|merged| {
                let mut value = merged.ended.value();
                value["adopted"] = merged.cause.is_none().into();
                value["cause"] = merged.cause.as_deref().into();
                value["attempts"] = merged.attempts.into();
                value
            }),
            "archive": finished.as_ref().err(),
        });
        let bytes = serde_json::to_vec(&value).expect("the run's record encodes");
        crate::store::replace_host(&self.directory.join("run.json"), &bytes)
            .and_then(|()| store(&self.plan.root, &record))
            .map_err(held)?;
        finished.map_err(Error::Held)?;
        Ok(value)
    }
}

/// Runs `campaign fuzz` for `plan` and returns the run's record.
///
/// # Errors
///
/// [`Error::Rejected`] for a root or archive path [`accepted`] refuses, a
/// root inside the archive or a cgroup root path custody refuses, before
/// the root is claimed, for a
/// root [`claim`] refuses, pens whose summed limits reach a limit of the
/// cgroup root or an ancestor, an archive that verification refuses, an
/// archive whose canonical path [`accepted`] refuses or that lies inside
/// the fuzz root, and an archive whose worker ends the [`merging`] probe
/// unsuccessfully;
/// [`Error::Store`] holding [`crate::store::Error::Busy`] while another
/// command holds the root or the cgroup root; [`Error::Held`] for a
/// failed signal block, a cgroup root that is no delegation with the cpu,
/// memory and pids controllers, an archive that fails verification for
/// another cause, a [`merging`] probe that returns
/// [`crate::archive::Unsuccessful::Failed`], each error of [`opened`] and
/// [`Session::advance`], a pen or worker that cannot start or be emptied,
/// a failed read of a pen's out-of-memory count, a failed write or
/// listing under the root, and a failed closing verification. A run that
/// writes its records, whatever the exits of its workers and merge,
/// stores its closing verification in `run.json`. A control
/// worker without a counters line is the [`Error::Rejected`] of
/// [`Session::controlled`], or [`Error::Held`] when the closing
/// verification fails too: the run keeps its number, its seeds and a
/// `control/` that holds that worker's `w/` and `w.stderr`, and writes
/// no `run.json`. A control whose stored finding cannot be checked is
/// the error of [`Session::judged`], with the control counts unchanged.
/// A missed control is no error: once the run's records are written and
/// the closing verification passed, the record returned ends [`MISSED`],
/// for which the command exits 1.
pub(in crate::campaign) fn fuzz(plan: &Plan) -> Result<Value, Error> {
    accepted(&plan.root, &plan.archive)?;
    outside_archive(&plan.root, &plan.archive)?;
    crate::custody::Custody::check_root(&plan.cgroup)?;
    crate::sys::block_interruptions().map_err(held)?;
    let _claimed = claim(&plan.root)?;
    let cgroup = pen::claim(&plan.cgroup)
        .map_err(held)?
        .ok_or(Error::Store(crate::store::Error::Busy))?;
    let limits = Limits {
        memory: plan.memory,
        processes: plan.processes,
    };
    fit(&cgroup, plan.workers, limits)?;
    let mut archive = crate::archive::Archive::load(&plan.archive).map_err(invalid)?;
    let (build, provenance) = (archive.pins().build, archive.record().provenance.clone());
    let approved = archive.verify().map_err(invalid)?;
    let template = approved.command();
    // The worker starts from the archive's canonical path, which reaches
    // the merge's shell line.
    accepted(&plan.root, Path::new(template.get_program()))?;
    let root = crate::store::canonical_host(&plan.root).map_err(held)?;
    if Path::new(template.get_program()).starts_with(root) {
        return Err(Error::Rejected(
            "the archive lies inside the fuzz root".into(),
        ));
    }
    let worker = Worker {
        program: template.get_program().to_owned(),
        environment: template
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.map(ToOwned::to_owned)))
            .collect(),
        gate: crate::store::canonical_host(Path::new("/proc/self/exe")).map_err(held)?,
        build,
        provenance,
    };
    merging(&worker, &plan.root, plan.memory)?;
    let session = opened(plan, &worker, limits)?;
    let ran = session
        .watched(&cgroup, 1, |_, pen, slot| {
            session.advance(Some((pen, slot)))
        })
        .and_then(|_| session.ran(&cgroup));
    let finished = approved
        .finish()
        .map_err(|error| format!("the archive after the run: {}", error.0));
    match ran {
        Ok(ran) => session.closed(&ran, finished),
        Err(error) => Err(match finished {
            Ok(()) => error,
            Err(changed) => Error::Held(format!("{error}; {changed}")),
        }),
    }
}

/// The record `fuzz.json` holds for the fuzz root `root`, or `None` for a
/// root no run has written. The read takes no lock and leaves the root's
/// files as they are, so it reads a root while a run holds it.
///
/// # Errors
///
/// As [`read`].
pub(in crate::campaign) fn status(root: &Path) -> Result<Option<Value>, Error> {
    Ok(read(root)?.map(|record| serde_json::to_value(record).expect("the record encodes")))
}

#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod tests;
