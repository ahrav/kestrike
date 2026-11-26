//! One launcher command: its artifact directory, its worker phases and
//! the evidence its artifact record names.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::class::{Stop, credit, incomplete, rejected};
use super::input::{RECORD, Staged, Stager, Values, worker_manifest};
use super::launch::{End, Interruptions, OUTPUT, launch};
use crate::archive::{Archive, Invalid};
use crate::exit::Sim;
use crate::protocol::{Listing, Run, Summary};
use crate::record::{Artifact, BOUND, Digest, Summarized, Text, Worker};
use crate::store::{
    self, Creation, Name, Store, Unreadable, create_dir, create_dirs, new_path, open_host,
    read_host, remove_dir,
};

/// The watchdog of a manifest that names none.
const WATCHDOG: Duration = Duration::from_secs(3600);
const LISTING_WATCHDOG: Duration = Duration::from_secs(60);
pub(super) const CAPABILITIES_PHASE: &str = "capabilities";
pub(super) const OUTPUT_STREAMS: [&str; 2] = ["stdout", "stderr"];

/// The most bytes of a reason the command keeps before the record escapes
/// it; worker text a reason quotes past it is cut.
pub(crate) const REASON: usize = 4096;

/// The permission bits of the staged input: owner read.
const INPUT_MODE: u32 = 0o400;

/// What a launcher command reads.
#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    /// `run`: a manifest to run into a new bundle.
    Manifest { archive: PathBuf, manifest: PathBuf },
    /// `inspect`: a raw bundle to inspect.
    Bundle { archive: PathBuf, bundle: PathBuf },
    /// Run a manifest into a new windowed session.
    Session {
        archive: PathBuf,
        manifest: PathBuf,
        output: Option<PathBuf>,
    },
    /// Replay a verified session into a new directory.
    ReplaySession {
        archive: PathBuf,
        source: PathBuf,
        output: Option<PathBuf>,
    },
    /// Branch a raw bundle at a named milestone.
    Branch {
        archive: PathBuf,
        bundle: PathBuf,
        milestone: String,
        suffixes: u32,
        siblings: u32,
        output: Option<PathBuf>,
    },
    /// Explore a raw bundle's bounded suffix tree from a named milestone.
    Explore {
        archive: PathBuf,
        bundle: PathBuf,
        milestone: String,
        output: Option<PathBuf>,
    },
    /// The verified archive’s capability contract.
    Capabilities(PathBuf),
    /// A fresh replay of a raw bundle.
    Replay { archive: PathBuf, bundle: PathBuf },
    /// Replay the frozen inputs of a verified artifact directory.
    FromRun(PathBuf),
    /// Reduces against the retained run's frozen manifest and archive.
    ReduceFromRun { source: PathBuf, output: PathBuf },
    /// Reduce a bundle into a new output directory.
    Reduce {
        archive: PathBuf,
        bundle: PathBuf,
        output: PathBuf,
    },
}

/// The options every launcher command takes.
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    /// The directory the artifact directory is created in.
    pub artifacts: PathBuf,
    pub run_id: Option<String>,
    pub watchdog: Option<Duration>,
}

/// A launcher command's class, why, and its artifact directory's absolute
/// path when the command opened one as a store.
#[derive(Debug)]
pub struct Ended {
    pub class: Sim,
    pub reason: String,
    pub artifact: Option<PathBuf>,
    /// The verified worker listing for a successful capabilities command.
    pub capabilities: Option<String>,
}

/// Runs `input`'s command under `options`. It blocks SIGINT and SIGTERM
/// for the rest of the process, so the process's first thread calls it
/// before it starts another, as the `campaign` binary does.
///
/// The calling process gives this function ownership of SIGCHLD and of
/// SIGINT and SIGTERM.
pub fn sim(input: &Input, options: &Options) -> Ended {
    let mut interruptions = match Interruptions::block() {
        Ok(interruptions) => interruptions,
        Err(error) => {
            return Ended {
                class: Sim::Incomplete,
                reason: format!("the signal setup failed: {error}"),
                artifact: None,
                capabilities: None,
            };
        }
    };
    let (id, store) = match open(options) {
        Ok(opened) => opened,
        Err(stop) => {
            let Stop(class, reason) = interrupted(&mut interruptions, stop);
            return Ended {
                class,
                reason,
                artifact: None,
                capabilities: None,
            };
        }
    };
    let mut command = Command {
        store,
        interruptions,
        watchdog: initial_watchdog(input, options.watchdog),
        archive: None,
        archive_path: None,
        comparison: None,
        session: None,
        session_original: None,
        capabilities: None,
        frozen: Vec::new(),
        manifest: None,
        output: None,
        bundle: None,
        summary: None,
        ruleless: false,
        workers: BTreeMap::new(),
        profile: None,
        maximum: None,
    };
    let (name, ran) = match input {
        Input::Manifest { archive, manifest } => ("run", command.run(archive, manifest)),
        Input::Bundle { archive, bundle } => ("inspect", command.inspect(archive, bundle)),
        Input::Capabilities(archive) => ("capabilities", command.capabilities(archive)),
        Input::Replay { archive, bundle } => {
            ("replay", command.replay_bundle(archive, bundle, None))
        }
        Input::Session {
            archive,
            manifest,
            output,
        } => (
            "session",
            command.session(archive, manifest, output.as_deref()),
        ),
        Input::ReplaySession {
            archive,
            source,
            output,
        } => (
            "replay-session",
            command.replay_session(archive, source, output.as_deref()),
        ),
        Input::Branch {
            archive,
            bundle,
            milestone,
            suffixes,
            siblings,
            output,
        } => (
            "branch",
            command.forked(
                archive,
                bundle,
                milestone,
                Some((*suffixes, *siblings)),
                output.as_deref(),
            ),
        ),
        Input::Explore {
            archive,
            bundle,
            milestone,
            output,
        } => (
            "explore",
            command.forked(archive, bundle, milestone, None, output.as_deref()),
        ),
        Input::FromRun(dir) => ("replay", command.triage_run(dir, None)),
        Input::ReduceFromRun { source, output } => {
            ("reduce", command.triage_run(source, Some(output)))
        }
        Input::Reduce {
            archive,
            bundle,
            output,
        } => ("reduce", command.reduce(archive, bundle, output, None)),
    };
    let ran = match command.stage_partial_bundle() {
        Ok(()) => ran,
        Err(Stop(_, staging)) => {
            let previous = match ran {
                Ok(Stop(_, reason)) | Err(Stop(_, reason)) => reason,
            };
            Err(incomplete(format!(
                "{previous}; bundle staging failed: {staging}"
            )))
        }
    };
    let Stop(class, mut reason) =
        interrupted(&mut command.interruptions, ran.unwrap_or_else(|stop| stop));
    // A reason can quote worker output, which the record's bound leaves no
    // room for in full.
    if reason.len() > REASON {
        reason.truncate(reason.floor_char_boundary(REASON));
        reason.push_str("...");
    }
    if let Some(comparison) = &mut command.comparison
        && !matches!(class, Sim::Counts | Sim::Complete)
    {
        comparison.status = text(class.name());
    }
    if !matches!(class, Sim::Counts | Sim::Complete)
        && let Some(session) = &mut command.session
    {
        session.complete = false;
        session.counts = false;
    }
    let artifact = Artifact {
        archive: command.archive,
        archive_path: command.archive_path,
        bundle: command.bundle,
        class: text(class.name()),
        command: text(name),
        summary: command
            .comparison
            .as_ref()
            .and_then(|comparison| comparison.original.clone())
            .or(command.summary),
        comparison: command.comparison,
        manifest: command.manifest,
        output: command.output,
        reason: text(&reason),
        run_id: text(id.as_str()),
        session: command.session,
        session_original: command.session_original,
        workers: command.workers,
    };
    let root = command.store.root();
    let (class, reason) = published(
        class,
        reason,
        command
            .store
            .create_record(root, &entry("artifact"), &artifact),
    );
    Ended {
        class,
        reason,
        artifact: Some(command.store.path().to_owned()),
        capabilities: command
            .capabilities
            .filter(|_| matches!(input, Input::Capabilities(_)) && class == Sim::Counts),
    }
}

fn initial_watchdog(input: &Input, supplied: Option<Duration>) -> Option<Duration> {
    supplied.or_else(|| matches!(input, Input::Capabilities(_)).then_some(LISTING_WATCHDOG))
}

fn published(class: Sim, reason: String, record: Result<Creation, store::Error>) -> (Sim, String) {
    match record {
        Ok(Creation::Created) => (class, reason),
        Ok(Creation::Existing) => (
            Sim::Incomplete,
            format!("{reason}; another artifact entry holds its name"),
        ),
        Err(error) => (
            Sim::Incomplete,
            format!("{reason}; the artifact record failed: {error}"),
        ),
    }
}

fn interrupted(interruptions: &mut Interruptions, stop: Stop) -> Stop {
    if let Some(signal) = interruptions.pending()
        && !matches!(stop.0, Sim::Watchdog | Sim::Interrupted)
    {
        Stop(Sim::Interrupted, format!("interrupted by signal {signal}"))
    } else {
        stop
    }
}

fn open(options: &Options) -> Result<(Name, Store), Stop> {
    if options.watchdog.is_some_and(|duration| {
        duration.is_zero() || duration > Duration::from_secs(u64::from(u32::MAX))
    }) {
        return Err(rejected(
            "the watchdog must be positive and at most u32::MAX seconds",
        ));
    }
    let run_id = options.run_id.clone().unwrap_or_else(|| {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        format!("local-{}-{}", seconds.as_secs(), std::process::id())
    });
    let Some(id) = Name::new(&run_id) else {
        return Err(Stop(
            Sim::Rejected,
            format!("the run id {run_id:?} is no file name"),
        ));
    };
    let named = options.artifacts.join(id.as_str());
    store::given_ancestors(&named).map_err(|error| {
        let class = if matches!(error, store::Error::Refused(_)) {
            Sim::Rejected
        } else {
            Sim::Incomplete
        };
        Stop(class, format!("the artifact path is refused: {error}"))
    })?;
    // The command prints the directory's absolute path as JSON text, so the
    // path must be UTF-8.
    let made = create_dirs(&options.artifacts).and_then(|()| new_path(&named));
    let dir = match made {
        Ok(dir) => dir,
        Err(error) => {
            let reason = format!(
                "the artifact directory {} is refused: {error}",
                named.display()
            );
            let class = match error.kind() {
                io::ErrorKind::AlreadyExists | io::ErrorKind::InvalidFilename => Sim::Rejected,
                _ => Sim::Incomplete,
            };
            return Err(Stop(class, reason));
        }
    };
    if dir.to_str().is_none() {
        return Err(rejected("the artifact path must be UTF-8"));
    }
    store::ancestors(&dir).map_err(|error| {
        let class = if matches!(error, store::Error::Refused(_)) {
            Sim::Rejected
        } else {
            Sim::Incomplete
        };
        Stop(class, format!("the artifact path is refused: {error}"))
    })?;
    create_dir(&dir).map_err(|error| {
        let class = if error.kind() == io::ErrorKind::AlreadyExists {
            Sim::Rejected
        } else {
            Sim::Incomplete
        };
        Stop(
            class,
            format!("creating the artifact directory failed: {error}"),
        )
    })?;
    let store = match Store::open(&dir) {
        Ok(store) => store,
        Err(error) => {
            // A refusal precedes the store's first write, so the directory
            // is still empty.
            let removed = remove_dir(&dir);
            let class = match (&error, &removed) {
                (store::Error::Refused(_), Ok(())) => Sim::Rejected,
                _ => Sim::Incomplete,
            };
            let mut reason = format!("the artifact directory: {error}");
            if let Err(error) = removed {
                reason.push_str(&format!("; removing the directory failed: {error}"));
            }
            return Err(Stop(class, reason));
        }
    };
    store.check_path().map_err(|error| {
        let class = if matches!(error, store::Error::Refused(_)) {
            Sim::Rejected
        } else {
            Sim::Incomplete
        };
        Stop(class, format!("the artifact path is refused: {error}"))
    })?;
    Ok((id, store))
}

pub(super) fn check_detail(value: &str, what: &str) -> Result<(), Stop> {
    if value.len() > REASON {
        Err(incomplete(format!("the {what} exceeds {REASON} bytes")))
    } else {
        Ok(())
    }
}

/// `value` as record text, with every character outside printable ASCII
/// escaped as `char::escape_default` escapes it.
pub(super) fn text(value: &str) -> Text {
    let mut escaped = String::with_capacity(value.len());
    for char in value.chars() {
        match char {
            ' '..='~' => escaped.push(char),
            _ => escaped.extend(char.escape_default()),
        }
    }
    Text::new(&escaped).expect("an escaped string is printable ASCII")
}

/// `name`, one of this module's entry names, as a store name.
pub(super) fn entry(name: &str) -> Name {
    Name::new(name).expect("an artifact entry's name is valid")
}

/// A worker phase that exited: its code and standard output.
pub(super) struct Ran {
    pub(super) code: i32,
    pub(super) stdout: String,
}

/// One command's store, signals, watchdog and the evidence its artifact
/// record names.
pub(super) struct Command {
    pub(super) store: Store,
    interruptions: Interruptions,
    /// The per-phase wait: `--watchdog`, else the manifest's value or an hour.
    /// Branch and explore triple the inherited wait for their fork phase.
    /// Standalone capabilities default to 60 seconds.
    pub(super) watchdog: Option<Duration>,
    pub(super) archive: Option<Digest>,
    archive_path: Option<Text>,
    capabilities: Option<String>,
    pub(super) comparison: Option<crate::record::Comparison>,
    pub(super) frozen: Vec<super::evidence::Frozen>,
    manifest: Option<Digest>,
    pub(super) output: Option<Text>,
    bundle: Option<Digest>,
    pub(super) summary: Option<Summarized>,
    /// Whether each summary this command keeps drops its unsuccessful rule.
    /// Triage admission sets it when the original's inspection prints a rule
    /// that the recorded original summary lacks, so the summaries of one
    /// comparison hold the same fields.
    pub(super) ruleless: bool,
    pub(super) session: Option<crate::record::SessionEvidence>,
    pub(super) session_original: Option<crate::record::SessionEvidence>,
    workers: BTreeMap<Text, Worker>,
    /// The profile the frozen manifest names.
    pub(super) profile: Option<String>,
    maximum: Option<u64>,
}

impl Command {
    fn capabilities(&mut self, path: &Path) -> Result<Stop, Stop> {
        let mut archive = self.load(path)?;
        let listing = self.listing(&mut archive)?;
        Ok(Stop(
            Sim::Counts,
            format!(
                "capabilities {}, manifest {}, summary {}, {} profiles",
                listing.capabilities,
                listing.manifest,
                listing.summary,
                listing.profiles.len()
            ),
        ))
    }

    pub(super) fn frozen_digest(&self, path: &Path) -> Result<Digest, Stop> {
        self.frozen
            .iter()
            .find(|file| file.path() == path)
            .map(super::evidence::Frozen::digest)
            .ok_or_else(|| incomplete("the bundle has no frozen digest"))
    }
    pub(super) fn difference(
        &self,
        committed: &Path,
        replayed: &Path,
    ) -> Result<Option<crate::record::Difference>, Stop> {
        super::evidence::difference(
            committed,
            replayed,
            self.frozen_digest(committed)?,
            self.frozen_digest(replayed)?,
        )
    }

    fn check_frozen(&self) -> Result<(), Stop> {
        for frozen in &self.frozen {
            frozen.check()?;
        }
        Ok(())
    }

    /// `sim run`: runs the manifest at `manifest` into the artifact
    /// directory's `bundle` and inspects it.
    fn run(&mut self, archive: &Path, manifest: &Path) -> Result<Stop, Stop> {
        let mut archive = self.load(archive)?;
        let read = read_host(manifest, BOUND)
            .map_err(|why| input_read_error(&why, "the manifest cannot be read"))?
            .ok_or_else(|| rejected(format!("{} does not exist", manifest.display())))?;
        let text =
            String::from_utf8(read).map_err(|_| rejected("the manifest is no UTF-8 text"))?;
        let listing = self.admit(&mut archive, &text, text.as_bytes(), "manifest")?;
        let (manifest, bundle) = (self.path("manifest"), self.path("bundle"));
        let args = [
            OsStr::new("--manifest"),
            manifest.as_os_str(),
            OsStr::new("--bundle"),
            bundle.as_os_str(),
        ];
        let ran = self.phase(&mut archive, "run", &args)?;
        match self.bundle_file()? {
            Some(opened) => {
                let maximum = self.maximum.expect("admission reads the frozen maximum");
                let staged = durable_bundle(&self.store, opened, maximum)?;
                self.bundle = Some(staged.digest);
            }
            None if ran.code == 2 => {
                self.check_frozen()?;
                return Err(rejected("the worker refused the manifest"));
            }
            None => {
                let reason = format!("the worker exited {} without a bundle", ran.code);
                return Err(incomplete(reason));
            }
        }
        self.frozen.push(super::evidence::Frozen::worker_bundle(
            bundle.clone(),
            self.bundle.expect("the bundle was staged"),
        )?);
        let summary = self.inspect_as(&mut archive, &listing, &bundle, &manifest, "inspect")?;
        match Run::parse(&ran.stdout, &listing) {
            Err(error) => Err(incomplete(format!(
                "the run form's output is refused: {error}"
            ))),
            Ok(Run::Panicked(at)) => Err(incomplete(format!("the run panicked at {at}"))),
            Ok(Run::Summary(printed)) if *printed != summary => Err(incomplete(
                "the run form's summary differs from the inspected bundle's",
            )),
            Ok(Run::Summary(_)) => Ok(credit(&summary, Some(ran.code))),
        }
    }

    /// `sim inspect`: stages the raw bundle at `source` as the artifact
    /// directory's `input` and inspects the copy.
    fn inspect(&mut self, archive: &Path, source: &Path) -> Result<Stop, Stop> {
        let mut archive = self.load(archive)?;
        let staged = self.stage(source)?;
        let frozen = worker_manifest(&staged.manifest);
        let listing = self.admit(&mut archive, &staged.manifest, &frozen, "bundle")?;
        let (input, manifest) = (self.path("input"), self.path("manifest"));
        let summary = self.inspect_as(&mut archive, &listing, &input, &manifest, "inspect")?;
        Ok(credit(&summary, None))
    }

    pub(super) fn stage(&mut self, source: &Path) -> Result<Staged, Stop> {
        let staged = stage_input(&self.store, source)?;
        self.bundle = Some(staged.digest);
        self.frozen.push(super::evidence::Frozen::bundle(
            source.to_owned(),
            staged.digest,
        )?);
        self.frozen.push(super::evidence::Frozen::worker_bundle(
            self.path("input"),
            staged.digest,
        )?);
        Ok(staged)
    }

    pub(super) fn admit(
        &mut self,
        archive: &mut Archive,
        text: &str,
        frozen: &[u8],
        what: &str,
    ) -> Result<Listing, Stop> {
        let values = Values::parse(text, what).map_err(rejected)?;
        values.pinned(&archive.pins(), what).map_err(rejected)?;
        self.freeze(&values, frozen)?;
        let listing = self.listing(archive)?;
        values.versioned(listing.manifest, what).map_err(rejected)?;
        Ok(listing)
    }

    /// Loads the archive at `path`.
    pub(super) fn load(&mut self, path: &Path) -> Result<Archive, Stop> {
        let archive = Archive::load(path)
            .map_err(|invalid| archive_failure(invalid, false, "the archive is refused"))?;
        self.archive = Some(archive.id());
        self.archive_path = Some(text(
            archive.path().to_str().expect("archive paths are ASCII"),
        ));
        Ok(archive)
    }

    /// The path of `name` in the artifact directory.
    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.store.path().join(name)
    }

    /// Freezes `bytes`, the manifest whose `values` were checked, as the
    /// artifact directory's `manifest`, and takes its watchdog unless
    /// `--watchdog` set one.
    fn freeze(&mut self, values: &Values<'_>, bytes: &[u8]) -> Result<(), Stop> {
        if bytes.len() as u64 > BOUND {
            return Err(rejected("the frozen manifest exceeds its byte bound"));
        }
        self.maximum = Some(values.maximum().map_err(rejected)?);
        let named = values.watchdog().map_err(rejected)?;
        if self.watchdog.is_none() {
            self.watchdog = Some(named.unwrap_or(WATCHDOG));
        }
        self.publish(&entry("manifest"), bytes)?;
        self.manifest = Some(Digest::of(bytes));
        self.frozen.push(super::evidence::Frozen::bounded_file(
            self.path("manifest"),
            Digest::of(bytes),
        )?);
        self.profile = values.profile().map(str::to_owned);
        Ok(())
    }

    fn stage_partial_bundle(&mut self) -> Result<(), Stop> {
        if self.bundle.is_some() {
            return Ok(());
        }
        let Some(opened) = self.bundle_file()? else {
            return Ok(());
        };
        self.store
            .sync_file(self.store.root(), &opened)
            .map_err(|error| {
                incomplete(format!(
                    "the partial bundle cannot be made durable: {error}"
                ))
            })?;
        let identity = opened.identity();
        let inherited = crate::sys::file_limit()
            .map_err(|error| incomplete(format!("the bundle file limit is unreadable: {error}")))?;
        let frozen = self
            .maximum
            .map_or(BOUND, |records| records.saturating_mul(RECORD as u64));
        let bound = inherited.min(frozen);
        let mut hashing = crate::record::Hashing::new(opened.take(bound.saturating_add(1)));
        let bytes = io::copy(&mut hashing, &mut io::sink())
            .map_err(|error| incomplete(format!("the partial bundle cannot be read: {error}")))?;
        if bytes > bound {
            return Err(incomplete(
                "the partial bundle exceeds its frozen or inherited file bound",
            ));
        }
        let digest = hashing.finish();
        let current = self
            .bundle_file()?
            .ok_or_else(|| incomplete("the partial bundle vanished"))?;
        if current.identity() != identity {
            return Err(incomplete("the partial bundle changed during staging"));
        }
        self.bundle = Some(digest);
        Ok(())
    }

    fn bundle_file(&self) -> Result<Option<store::Opened>, Stop> {
        self.store
            .open_file(self.store.root(), &entry("bundle"))
            .map_err(|why| incomplete(format!("the bundle is unreadable: {why:?}")))
    }

    /// Publishes `bytes` as the new artifact entry `name`.
    pub(super) fn publish(&self, name: &Name, bytes: &[u8]) -> Result<(), Stop> {
        match self.store.create_once(self.store.root(), name, bytes) {
            Ok(Creation::Created) => Ok(()),
            failed => Err(incomplete(format!(
                "the artifact entry {} failed: {failed:?}",
                name.as_str()
            ))),
        }
    }

    /// The capability listing phase.
    fn listing(&mut self, archive: &mut Archive) -> Result<Listing, Stop> {
        let ran = self.phase(archive, CAPABILITIES_PHASE, &[OsStr::new("--capabilities")])?;
        if ran.code != 0 {
            let reason = format!(
                "the worker exited {} without a capability listing",
                ran.code
            );
            return Err(incomplete(reason));
        }
        let listing = Listing::parse(&ran.stdout)
            .map_err(|error| incomplete(format!("the capability listing is refused: {error}")))?;
        self.capabilities = Some(ran.stdout);
        Ok(listing)
    }

    /// The inspect phase over `bundle` under the frozen `manifest`, and
    /// the summary it prints.
    pub(super) fn inspect_as(
        &mut self,
        archive: &mut Archive,
        listing: &Listing,
        bundle: &Path,
        manifest: &Path,
        name: &str,
    ) -> Result<Summary, Stop> {
        let args = [
            OsStr::new("--inspect"),
            bundle.as_os_str(),
            OsStr::new("--manifest"),
            manifest.as_os_str(),
        ];
        let ran = self.phase(archive, name, &args)?;
        if ran.code != 0 {
            return Err(incomplete(format!(
                "the worker exited {} refusing the bundle",
                ran.code
            )));
        }
        let summary = Summary::parse(&ran.stdout, listing)
            .map_err(|error| incomplete(format!("the bundle summary is refused: {error}")))?;
        if let Some(cause) = &summary.cause {
            check_detail(cause, "summary cause")?;
        }
        let first_failure = super::evidence::first_failure(bundle, self.frozen_digest(bundle)?);
        self.summary = Some(Summarized {
            cause: summary.cause.as_deref().map(text),
            identity: summary.identity.as_ref().map(|id| text(id.as_str())),
            first_failure: first_failure.as_ref().ok().cloned().flatten(),
            counts: summary.counts,
            decisions: summary.decisions,
            digest: summary.digest,
            ledger: summary.ledger.as_ref().map(|ledger| text(ledger.verdict())),
            terminal: text(&summary.terminal.to_string()),
            unsuccessful: summary.unsuccessful.clone().filter(|_| !self.ruleless),
        });
        first_failure?;
        // The listing judges the ledger by the profile the summary names,
        // so that profile must be the one the frozen manifest runs.
        if summary.profile.as_deref() != self.profile.as_deref() {
            return Err(incomplete(format!(
                "the summary names profile {:?}; the manifest runs {:?}",
                summary.profile, self.profile
            )));
        }
        Ok(summary)
    }

    /// Runs the archived worker with `args` as phase `name`, keeping its
    /// outputs and its end in the artifact directory.
    pub(super) fn phase(
        &mut self,
        archive: &mut Archive,
        name: &str,
        args: &[&OsStr],
    ) -> Result<Ran, Stop> {
        if let Some(signal) = self.interruptions.pending() {
            return Err(Stop(
                Sim::Interrupted,
                format!("interrupted by signal {signal} before {name}"),
            ));
        }
        self.store.check_path().map_err(|error| {
            incomplete(format!(
                "the artifact path is refused before {name}: {error}"
            ))
        })?;
        self.check_frozen()?;
        let approved = archive.verify().map_err(|invalid| {
            archive_failure(
                invalid,
                !self.workers.is_empty(),
                &format!("the archive is refused before {name}"),
            )
        })?;
        let mut command = approved.command();
        command.args(args);
        let watchdog = self.watchdog.unwrap_or(WATCHDOG);
        let launched = launch(
            command,
            self.store.path(),
            watchdog,
            &mut self.interruptions,
        );
        use std::os::unix::process::ExitStatusExt;
        let checked_archive = approved.finish();
        let checked_input = self.check_frozen();
        let (exit, signal) = match launched.end {
            End::Exited(code) => (u64::try_from(code).ok(), None),
            End::Signaled(signal) => (None, u64::try_from(signal).ok()),
            End::Escaped => launched.status.map_or((None, None), |status| {
                (
                    status.code().and_then(|code| u64::try_from(code).ok()),
                    status
                        .signal()
                        .and_then(|signal| u64::try_from(signal).ok()),
                )
            }),
            _ => (None, None),
        };
        // The record names every phase that started, so the worker enters
        // the map before its streams publish: a failed stream entry stops
        // the phase with the worker already represented.
        let phase = text(name);
        self.workers.insert(
            phase.clone(),
            Worker {
                ended: text(launched.end.name()),
                exit,
                signal,
                stderr: Digest::of(&launched.stderr),
                stdout: Digest::of(&launched.stdout),
            },
        );
        let streams: [&[u8]; OUTPUT_STREAMS.len()] = [&launched.stdout, &launched.stderr];
        for (stream, bytes) in OUTPUT_STREAMS.into_iter().zip(streams) {
            let entry = Artifact::stream_name(&phase, stream)
                .ok_or_else(|| incomplete("the evidence stream name is invalid"))?;
            self.publish(&entry, bytes)?;
        }
        let cleanup = if launched.drained && launched.closed {
            String::new()
        } else {
            format!(
                "; group drained={}, pipes closed={}",
                launched.drained, launched.closed
            )
        };
        let stopped = |class, mut reason: String| {
            if let Err(error) = &checked_archive {
                reason.push_str(&format!("; closing archive check: {error}"));
            }
            if let Err(error) = &checked_input {
                reason.push_str(&format!("; closing input check: {}", error.1));
            }
            Stop(class, reason)
        };
        let code = match launched.end {
            End::Exited(code) => code,
            End::Signaled(signal) => {
                return Err(stopped(
                    Sim::Incomplete,
                    format!("{name} died from signal {signal}"),
                ));
            }
            End::Watchdog => {
                let reason = format!("{name} outlived the {watchdog:?} watchdog{cleanup}");
                return Err(stopped(Sim::Watchdog, reason));
            }
            End::Interrupted(signal) => {
                let reason = format!("interrupted by signal {signal} during {name}{cleanup}");
                return Err(stopped(Sim::Interrupted, reason));
            }
            End::Oversized => {
                let reason = format!("{name} wrote more than {OUTPUT} bytes to a stream{cleanup}");
                return Err(stopped(Sim::Incomplete, reason));
            }
            End::Escaped => {
                let reason = format!("{name}'s cleanup exceeded its bound{cleanup}");
                return Err(stopped(Sim::Incomplete, reason));
            }
            End::Failed(error) => {
                return Err(stopped(
                    Sim::Incomplete,
                    format!("{name} failed to run: {error}{cleanup}"),
                ));
            }
        };
        self.store.check_path().map_err(|error| {
            incomplete(format!(
                "the artifact path is refused after {name}: {error}"
            ))
        })?;
        checked_archive.map_err(|invalid| {
            incomplete(format!(
                "the archive no longer verifies after {name}: {invalid}"
            ))
        })?;
        checked_input?;
        let stdout = String::from_utf8(launched.stdout)
            .map_err(|_| incomplete(format!("{name} printed bytes that are no UTF-8 text")))?;
        Ok(Ran { code, stdout })
    }
}

pub(super) fn durable_triage_bundle(store: &Store, path: &Path) -> Result<Staged, Stop> {
    let (opened, parent) = store::open_evidence(path).map_err(|error| {
        incomplete(format!(
            "the candidate bundle {} is unreadable: {error:?}",
            path.display()
        ))
    })?;
    store.sync_evidence(&parent, &opened).map_err(|error| {
        incomplete(format!(
            "the candidate bundle cannot be made durable: {error}"
        ))
    })?;
    let mut stager = Stager::new(opened);
    io::copy(&mut stager, &mut io::sink()).map_err(|error| incomplete(error.to_string()))?;
    stager.finish().map_err(incomplete)
}

fn durable_bundle(
    store: &Store,
    opened: store::Opened,
    records: u64,
) -> Result<super::input::Staged, Stop> {
    store
        .sync_file(store.root(), &opened)
        .map_err(|error| incomplete(format!("the bundle cannot be made durable: {error}")))?;
    let maximum = records.saturating_mul(RECORD as u64);
    let mut stager = Stager::new(opened.take(maximum.saturating_add(RECORD as u64)));
    io::copy(&mut stager, &mut io::sink())
        .map_err(|error| incomplete(format!("the bundle cannot be read: {error}")))?;
    let staged = stager.finish().map_err(incomplete)?;
    if staged.bytes > maximum {
        return Err(incomplete(
            "the bundle exceeds the frozen manifest's record maximum",
        ));
    }
    Ok(staged)
}

pub(super) fn input_store_error(error: store::Error, context: &str) -> Stop {
    match error {
        store::Error::Unreadable(store::Unreadable::Io(error))
            if error.kind() == io::ErrorKind::AlreadyExists =>
        {
            rejected(format!("{context}: {error}"))
        }
        store::Error::Unreadable(error) => input_read_error(&error, context),
        store::Error::Refused(error) => rejected(format!("{context}: {error:?}")),
        error => incomplete(format!("{context}: {error}")),
    }
}

fn archive_failure(invalid: Invalid, used: bool, context: &str) -> Stop {
    let class = invalid.exit(used);
    Stop(class, format!("{context}: {invalid}"))
}

/// Stages the raw bundle at `source` as the store's `input`, hashing and
/// scanning it as it is copied.
///
/// # Errors
///
/// An unreadable source is classed by [`input_read_error`]; a failed copy or
/// source read is incomplete evidence. A bundle the scan refuses is a
/// rejected input when the source still has the identity it was opened
/// with, and incomplete evidence when the source changed or cannot be
/// reopened, since the scan then read a bundle its caller never named.
fn stage_input(store: &Store, source: &Path) -> Result<Staged, Stop> {
    let opened =
        open_host(source).map_err(|why| input_read_error(&why, "the bundle cannot be read"))?;
    let before = opened.identity();
    let mut stager = Stager::new(opened);
    let copied = store.copy_once(store.root(), &entry("input"), &mut stager, INPUT_MODE);
    if !matches!(copied, Ok(Creation::Created)) {
        return Err(incomplete(format!(
            "the bundle's staging failed: {copied:?}"
        )));
    }
    if let Some(error) = stager.read_error() {
        return Err(incomplete(format!("the input source read failed: {error}")));
    }
    stager.finish().map_err(|reason| match open_host(source) {
        Ok(after) if after.identity() == before => rejected(reason),
        Ok(_) => incomplete(format!(
            "{} changed while it was staged: {reason}",
            source.display()
        )),
        Err(why) => incomplete(format!(
            "{} cannot be reopened after staging: {why:?}; {reason}",
            source.display()
        )),
    })
}

pub(super) fn input_read_error(why: &Unreadable, context: &str) -> Stop {
    let class = if why.faulted() {
        Sim::Incomplete
    } else {
        Sim::Rejected
    };
    Stop(class, format!("{context}: {why:?}"))
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;

/// Admits a new printable-ASCII output path before any worker starts.
/// An entry inside the artifact namespace is admitted only at the supplied
/// command default. Commands with no artifact default pass `None`.
pub(super) fn new_output(
    store: &Store,
    path: &Path,
    what: &str,
    default: Option<&Path>,
) -> Result<PathBuf, Stop> {
    let target = store::vacant_evidence(path)
        .map_err(|error| input_store_error(error, &format!("the {what} output is refused")))?;
    if target.starts_with(store.path()) && default != Some(target.as_path()) {
        return Err(rejected("the output path names a reserved artifact entry"));
    }
    if target.to_str().and_then(Text::new).is_none() {
        return Err(rejected("the output path must be printable ASCII"));
    }
    Ok(target)
}
