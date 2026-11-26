//! The replay and reduction commands compare frozen inputs with the recorded run.

use super::class::{Stop, credit, incomplete, rejected};
use super::command::{
    Command, check_detail, durable_triage_bundle, entry, input_read_error, input_store_error,
    new_output, text,
};
use super::evidence::Frozen;
use super::input::{Stager, Values, worker_manifest};
use crate::archive::Archive;
use crate::exit::Sim;
use crate::protocol::{
    Infrastructure, Listing, Outcome, ReduceResult, ReplayResult, Run, Summary, Terminal,
};
use crate::record::{Artifact, BOUND, Comparison, Digest};
use crate::store::{Creation, View, vacant_evidence};
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

/// Frozen inputs and worker evidence read from a verified artifact.
pub(super) struct Original<'a> {
    record: &'a Artifact,
    manifest: &'a [u8],
    run: Option<String>,
    baseline: &'a crate::record::Summarized,
}
struct Candidate {
    manifest: PathBuf,
    digest: Digest,
    records: u64,
    scenario: String,
}
enum Failure {
    Violation(crate::record::Text),
    Panic(crate::record::Text),
}
impl Failure {
    fn panic(identity: &str) -> Result<Self, Stop> {
        check_detail(identity, "panic identity")?;
        Ok(Self::Panic(panic_identity(identity)))
    }
    fn kind(&self) -> &'static str {
        match self {
            Self::Violation(_) => "violation",
            Self::Panic(_) => "panic",
        }
    }
    fn identity(&self) -> &crate::record::Text {
        match self {
            Self::Violation(identity) | Self::Panic(identity) => identity,
        }
    }
}
struct Admitted {
    archive: Archive,
    listing: Listing,
    original: Summary,
    panic: Option<crate::record::Text>,
}
enum PanicVerdict {
    Panicked(String),
    Passed,
    Different,
}
enum ReplayVerdict {
    Reproduced(Stop),
    Other(Stop),
}
impl ReplayVerdict {
    fn stop(self) -> Stop {
        match self {
            Self::Reproduced(stop) | Self::Other(stop) => stop,
        }
    }
}

impl Command {
    /// Resolves the archive and frozen input from a verified run artifact.
    /// A held record, changed input or another archive identity refuses the run.
    pub(super) fn triage_run(
        &mut self,
        path: &Path,
        reduction: Option<&Path>,
    ) -> Result<Stop, Stop> {
        let view = View::open(path)
            .map_err(|error| input_store_error(error, "the run directory is refused"))?;
        let verified = view
            .read_record::<Artifact>(view.root(), &entry("artifact"))
            .map_err(|held| {
                let class = match &held {
                    crate::record::Held::Unreadable(error) if error.faulted() => Sim::Incomplete,
                    _ => Sim::Rejected,
                };
                Stop(class, format!("the artifact is held: {held:?}"))
            })?
            .ok_or_else(|| rejected("the run has no artifact"))?;
        let record = verified.record();
        if view.path().file_name().and_then(OsStr::to_str) != Some(record.run_id.as_str()) {
            return Err(rejected("the artifact names another run id"));
        }
        let archive = record
            .archive_path
            .as_ref()
            .ok_or_else(|| rejected("the run records no archive path"))?;
        let name = match record.command.as_str() {
            "run" => "bundle",
            "inspect" | "replay" | "reduce" => "input",
            _ => return Err(rejected("the artifact records no replayable command")),
        };
        let baseline = if matches!(record.command.as_str(), "replay" | "reduce") {
            record
                .comparison
                .as_ref()
                .and_then(|comparison| comparison.original.as_ref())
        } else {
            record.summary.as_ref()
        };
        let baseline = baseline.ok_or_else(|| rejected("the run records no original summary"))?;
        let bundle = view.path().join(name);
        let manifest = view.path().join("manifest");
        let bytes = view
            .read(view.root(), &entry("manifest"), BOUND)
            .map_err(|error| input_read_error(&error, "the run manifest is refused"))?
            .ok_or_else(|| rejected("the run has no frozen manifest"))?;
        if Some(Digest::of(bytes.bytes())) != record.manifest {
            return Err(rejected("the run manifest differs from the artifact"));
        }
        self.frozen.push(Frozen::bounded_file(
            manifest,
            record.manifest.expect("the digest was checked"),
        )?);
        let run = match record.workers.get(&text("run")) {
            Some(worker) if record.command.as_str() == "run" && worker.exit == Some(3) => {
                let read = view
                    .read(view.root(), &entry("run.stdout"), BOUND)
                    .map_err(|error| input_read_error(&error, "the run output is refused"))?
                    .ok_or_else(|| rejected("the run output is missing"))?;
                if Digest::of(read.bytes()) != worker.stdout {
                    return Err(rejected("the run output differs from the artifact"));
                }
                self.frozen.push(Frozen::bounded_file(
                    view.path().join("run.stdout"),
                    worker.stdout,
                )?);
                Some(
                    String::from_utf8(read.bytes().to_vec())
                        .map_err(|_| rejected("the run output is no UTF-8 text"))?,
                )
            }
            _ => None,
        };
        let recorded_bundle = record
            .bundle
            .ok_or_else(|| rejected("the run records no bundle digest"))?;
        let opened = view
            .open_file(view.root(), &entry(name))
            .map_err(|error| input_read_error(&error, "the run bundle is refused"))?
            .ok_or_else(|| rejected("the run has no bundle"))?;
        let staged = read_original_bundle(opened)?;
        if staged.digest != recorded_bundle {
            return Err(rejected("the frozen bundle differs from the recorded run"));
        }
        self.frozen
            .push(Frozen::worker_bundle(bundle.clone(), recorded_bundle)?);
        let original = Some(Original {
            record,
            manifest: bytes.bytes(),
            run,
            baseline,
        });
        match reduction {
            Some(output) => self.reduce(Path::new(archive.as_str()), &bundle, output, original),
            None => self.replay_bundle(Path::new(archive.as_str()), &bundle, original),
        }
    }
    /// Replays a staged bundle or the verified input named by an artifact.
    pub(super) fn replay_bundle(
        &mut self,
        path: &Path,
        source: &Path,
        expected: Option<Original<'_>>,
    ) -> Result<Stop, Stop> {
        let output = record_path(&self.path("replay").join("replay.bundle"))?;
        let Admitted {
            mut archive,
            listing,
            original,
            panic,
        } = self.admit_triage(path, source, expected)?;
        if original.terminal == Terminal::Infrastructure(Infrastructure::Truncated) {
            if let Some(panic) = panic {
                return self.replay_panic(&mut archive, &listing, &original, &panic, output);
            }
            return Err(incomplete(
                "the original records no complete terminal or panic identity",
            ));
        }
        self.replay_checked(
            &mut archive,
            &listing,
            &self.path("input"),
            &original,
            "replay",
            Some(output),
        )
        .map(ReplayVerdict::stop)
    }

    fn admit_triage(
        &mut self,
        path: &Path,
        source: &Path,
        expected: Option<Original<'_>>,
    ) -> Result<Admitted, Stop> {
        self.comparison = Some(Comparison {
            candidate: None,
            output: None,
            divergence: None,
            failure_identity: None,
            failure_kind: None,
            observed: None,
            original: None,
            status: text("incomplete"),
        });
        let mut archive = self.load(path)?;
        if let Some(expected) = &expected
            && expected.record.archive != self.archive
        {
            return Err(rejected("the archive differs from the recorded run"));
        }
        let staged = self.stage(source)?;
        if let Some(expected) = &expected
            && expected.record.bundle != Some(staged.digest)
        {
            return Err(rejected("the frozen bundle differs from the recorded run"));
        }
        let input = self.path("input");
        let frozen = match expected {
            Some(ref expected) => expected.manifest.to_vec(),
            None => worker_manifest(&staged.manifest),
        };
        let listing = self.admit(&mut archive, &staged.manifest, &frozen, "bundle")?;
        let manifest = self.path("manifest");
        let original = self.inspect_as(
            &mut archive,
            &listing,
            &input,
            &manifest,
            "inspect-original",
        )?;
        let mut facts = self.summary.clone().expect("inspection stored its summary");
        self.ruleless = facts.unsuccessful.is_some()
            && expected
                .as_ref()
                .is_some_and(|expected| expected.baseline.unsuccessful.is_none());
        if self.ruleless {
            facts.unsuccessful = None;
            self.summary = Some(facts.clone());
        }
        self.compared().original = Some(
            expected
                .as_ref()
                .map_or_else(|| facts.clone(), |expected| expected.baseline.clone()),
        );
        if let Some(expected) = &expected
            && expected.baseline != &facts
        {
            self.compared().observed = Some(facts);
            return Err(incomplete(
                "the original inspection differs from the recorded summary",
            ));
        }
        if original.counts && credit(&original, None).0 == Sim::Incomplete {
            return Err(incomplete(
                "the original counts a bundle without a decision",
            ));
        }
        let panic = match expected {
            Some(expected) => {
                if let Some(stdout) = expected.run
                    && let Run::Panicked(identity) = Run::parse(&stdout, &listing)
                        .map_err(|error| incomplete(error.to_string()))?
                {
                    Some(Failure::panic(&identity)?.identity().clone())
                } else {
                    expected
                        .record
                        .comparison
                        .as_ref()
                        .filter(|comparison| {
                            comparison
                                .failure_kind
                                .as_ref()
                                .is_some_and(|kind| kind.as_str() == "panic")
                        })
                        .and_then(|comparison| comparison.failure_identity.clone())
                }
            }
            None => None,
        };
        if let Some(identity) = &panic {
            if original.terminal != Terminal::Infrastructure(Infrastructure::Truncated) {
                return Err(incomplete(
                    "the recorded panic disagrees with the original terminal",
                ));
            }
            self.set_failure(&Failure::Panic(identity.clone()));
        }
        Ok(Admitted {
            archive,
            listing,
            original,
            panic,
        })
    }

    /// Reduces the staged bundle into a new directory and verifies the candidate.
    pub(super) fn reduce(
        &mut self,
        path: &Path,
        source: &Path,
        output: &Path,
        expected: Option<Original<'_>>,
    ) -> Result<Stop, Stop> {
        let target = new_output(&self.store, output, "reduction", None)?;
        let output = record_path(&target.join("regression.bundle"))?;
        let Admitted {
            mut archive,
            listing,
            original,
            panic,
        } = self.admit_triage(path, source, expected)?;
        let input = self.path("input");
        if original.terminal == Terminal::Infrastructure(Infrastructure::Truncated) {
            return self.reduce_panic(
                &mut archive,
                &listing,
                &target,
                output,
                &original,
                panic.as_ref(),
            );
        }
        if let ReplayVerdict::Other(stop) =
            self.replay_checked(&mut archive, &listing, &input, &original, "baseline", None)?
        {
            return Ok(stop);
        }
        let Some(identity) = failure(&original) else {
            return self.verdict(
                "unreducible",
                Sim::Complete,
                "the reproduced original records no complete failure identity",
            );
        };
        self.set_failure(&Failure::Violation(text(&identity)));
        let Some(reduced) = self.reduce_worker(&mut archive, &input, &target)? else {
            return self.verdict(
                "unreducible",
                Sim::Complete,
                "the worker could not reduce the reproduced failure",
            );
        };
        let candidate = target.join("regression.bundle");
        let candidate_evidence =
            self.guard_bundle(&candidate, &archive, &listing, "candidate.manifest")?;
        self.check_reduction(&reduced, &candidate_evidence, false)?;
        self.compared().output = Some(output);
        self.compared().candidate = Some(candidate_evidence.digest);
        let observed = self.inspect_as(
            &mut archive,
            &listing,
            &candidate,
            &candidate_evidence.manifest,
            "inspect-candidate",
        )?;
        let facts = self.summary.clone();
        self.compared().observed = facts;
        if observed.counts && credit(&observed, None).0 == Sim::Incomplete {
            return Err(incomplete(
                "the candidate counts a bundle without a decision",
            ));
        }
        if observed.terminal.passes() {
            return self.verdict("unreproduced", Sim::Complete, "the candidate passes");
        }
        if matches!(
            observed.terminal,
            Terminal::Infrastructure(Infrastructure::Truncated | Infrastructure::Sink)
        ) {
            return Err(incomplete("the candidate is incomplete"));
        }
        if failure(&observed).as_deref() != Some(identity.as_str()) {
            return self.verdict(
                "diverged",
                Sim::Complete,
                "the candidate has another failure kind or identity",
            );
        }
        if let ReplayVerdict::Other(stop) = self.replay_checked(
            &mut archive,
            &listing,
            &candidate,
            &observed,
            "candidate-replay",
            None,
        )? {
            return Ok(stop);
        }
        self.verdict(
            "reduced",
            Sim::Complete,
            &format!(
                "reduced with equal failure kind and identity into {}{}",
                target.display(),
                if reduced.bounded { " (bounded)" } else { "" },
            ),
        )
    }
    /// Compares the full summaries and semantic records of one fresh replay.
    fn replay_checked(
        &mut self,
        archive: &mut Archive,
        listing: &Listing,
        input: &Path,
        original: &Summary,
        name: &str,
        output: Option<crate::record::Text>,
    ) -> Result<ReplayVerdict, Stop> {
        let target = self.path(name);
        let ran = self.phase(
            archive,
            name,
            &[
                OsStr::new("--replay"),
                input.as_os_str(),
                OsStr::new("--output"),
                target.as_os_str(),
            ],
        )?;
        if ran.code == 2 {
            return Err(refused(name, "the worker refused replay"));
        }
        let result = ReplayResult::parse(&ran.stdout)
            .map_err(|error| incomplete(format!("the replay result is refused: {error}")))?;
        let reproduced = matches!(result, ReplayResult::Reproduced(_));
        if !matches!(
            (ran.code, &result),
            (0, ReplayResult::Reproduced(_))
                | (1, ReplayResult::Diverged { .. } | ReplayResult::Panicked(_))
        ) {
            return Err(incomplete(format!(
                "the worker exited {} with a contradictory replay result",
                ran.code
            )));
        }
        let bundle = target.join("replay.bundle");
        let replay_manifest =
            self.guard_bundle(&bundle, archive, listing, &format!("{name}.manifest"))?;
        let observed = self.inspect_as(
            archive,
            listing,
            &bundle,
            &replay_manifest.manifest,
            &format!("inspect-{name}"),
        )?;
        self.compared().observed = self.summary.clone();
        if !result.agrees(&observed) {
            return Err(incomplete(
                "the replay claim differs from the inspected terminal or breach",
            ));
        }
        let facts = self.summary.clone().expect("inspection stored facts");
        let compared = self.difference(input, &bundle)?;
        let comparison = self.compared();
        comparison.observed = Some(facts);
        comparison.divergence = compared;
        if let Some(output) = output {
            comparison.output = Some(output);
            comparison.candidate = Some(replay_manifest.digest);
        }
        let same = original == &observed && comparison.divergence.is_none();
        let credited = credit(&observed, None);
        if observed.counts && credited.0 == Sim::Incomplete {
            return Err(credited);
        }
        if let ReplayResult::Panicked(_) = result {
            if observed.terminal != Terminal::Infrastructure(Infrastructure::Truncated) {
                return Err(incomplete(
                    "the panic line disagrees with the replayed terminal",
                ));
            }
            return self
                .verdict("diverged", Sim::Complete, "the fresh replay panicked")
                .map(ReplayVerdict::Other);
        }
        if same && reproduced {
            if credited.0 == Sim::Incomplete {
                return Err(credited);
            }
            comparison.status = text("reproduced");
            Ok(ReplayVerdict::Reproduced(credited))
        } else if !original.terminal.passes() && observed.terminal.passes() {
            self.verdict("unreproduced", Sim::Complete, "the fresh replay passes")
                .map(ReplayVerdict::Other)
        } else if matches!(
            observed.terminal,
            Terminal::Infrastructure(Infrastructure::Truncated | Infrastructure::Sink)
        ) {
            Err(incomplete("the fresh replay is incomplete"))
        } else {
            self.verdict(
                "diverged",
                Sim::Complete,
                &if same {
                    format!("{name}: the worker reported divergence while the independent comparison agrees")
                } else {
                    format!("{name}: the fresh replay differs from its input")
                },
            )
            .map(ReplayVerdict::Other)
        }
    }

    fn replay_panic(
        &mut self,
        archive: &mut Archive,
        listing: &Listing,
        original: &Summary,
        expected_identity: &crate::record::Text,
        output: crate::record::Text,
    ) -> Result<Stop, Stop> {
        match self.store.mkdir(self.store.root(), &entry("replay")) {
            Ok(Creation::Created) => {}
            failed => {
                return Err(incomplete(format!(
                    "the replay directory failed: {failed:?}"
                )));
            }
        }
        let bundle = self.path("replay").join("replay.bundle");
        let (verdict, candidate, observed) =
            self.panic_run(archive, listing, &self.path("manifest"), &bundle, "replay")?;
        self.compared().output = Some(output);
        self.compared().candidate = Some(candidate.digest);
        let compared = self.difference(&self.path("input"), &bundle)?;
        let comparison = self.compared();
        comparison.divergence = compared;
        match verdict {
            PanicVerdict::Passed => self.verdict(
                "unreproduced",
                Sim::Complete,
                "the fresh panic rerun passes",
            ),
            PanicVerdict::Different => self.verdict(
                "diverged",
                Sim::Complete,
                "the fresh rerun has another failure kind",
            ),
            PanicVerdict::Panicked(identity)
                if panic_identity(&identity) == *expected_identity
                    && comparison.divergence.is_none()
                    && observed == *original =>
            {
                self.verdict(
                    "reproduced",
                    Sim::Complete,
                    "the fresh rerun reproduces the recorded panic and bundle",
                )
            }
            PanicVerdict::Panicked(_) => self.verdict(
                "diverged",
                Sim::Complete,
                "the fresh rerun has another panic identity or bundle",
            ),
        }
    }

    fn guard_bundle(
        &mut self,
        bundle: &Path,
        archive: &Archive,
        listing: &Listing,
        manifest_name: &str,
    ) -> Result<Candidate, Stop> {
        let staged = durable_triage_bundle(&self.store, bundle)?;
        let values = Values::parse(&staged.manifest, "candidate").map_err(incomplete)?;
        values
            .pinned(&archive.pins(), "candidate")
            .map_err(incomplete)?;
        values
            .versioned(listing.manifest, "candidate")
            .map_err(incomplete)?;
        self.frozen
            .push(Frozen::worker_bundle(bundle.to_owned(), staged.digest)?);
        self.profile = values.profile().map(str::to_owned);
        let manifest = self.path(manifest_name);
        let frozen = worker_manifest(&staged.manifest);
        if frozen.len() as u64 > BOUND {
            return Err(incomplete("the candidate manifest exceeds its byte bound"));
        }
        self.publish(&super::command::entry(manifest_name), &frozen)?;
        self.frozen
            .push(Frozen::bounded_file(manifest.clone(), Digest::of(&frozen))?);
        Ok(Candidate {
            manifest,
            digest: staged.digest,
            records: staged.bytes / super::input::RECORD as u64,
            scenario: values.scenario().unwrap_or_default().to_owned(),
        })
    }
    fn reduce_worker(
        &mut self,
        archive: &mut Archive,
        input: &Path,
        target: &Path,
    ) -> Result<Option<ReduceResult>, Stop> {
        vacant_evidence(target).map_err(|error| {
            incomplete(format!(
                "the reduction output changed before reduce: {error}"
            ))
        })?;
        let ran = self.phase(
            archive,
            "reduce",
            &[
                OsStr::new("--reduce"),
                input.as_os_str(),
                OsStr::new("--output"),
                target.as_os_str(),
            ],
        )?;
        if ran.code == 1 {
            if !ran.stdout.is_empty() {
                return Err(incomplete(
                    "the worker reported a reduction with an unreducible exit",
                ));
            }
            return Ok(None);
        }
        if ran.code == 2 {
            return Err(rejected("the worker refused reduce"));
        }
        if ran.code != 0 {
            return Err(incomplete(format!(
                "the worker exited {} reducing the failure",
                ran.code
            )));
        }
        ReduceResult::parse(&ran.stdout)
            .map(Some)
            .map_err(|error| incomplete(format!("the reduction result is refused: {error}")))
    }

    fn check_reduction(
        &self,
        result: &ReduceResult,
        candidate: &Candidate,
        panic: bool,
    ) -> Result<(), Stop> {
        if result.records != candidate.records
            || result.scenario != candidate.scenario
            || result.panic.is_some() != panic
        {
            return Err(incomplete(
                "the reduction result differs from the candidate records, scenario or failure kind",
            ));
        }
        Ok(())
    }

    fn set_failure(&mut self, failure: &Failure) {
        self.compared().failure_kind = Some(text(failure.kind()));
        self.compared().failure_identity = Some(failure.identity().clone());
    }

    fn compared(&mut self) -> &mut Comparison {
        self.comparison
            .as_mut()
            .expect("admission initialized the comparison")
    }
    fn verdict(&mut self, status: &str, class: Sim, reason: &str) -> Result<Stop, Stop> {
        self.compared().status = text(status);
        Ok(Stop(class, reason.into()))
    }
    fn reduce_panic(
        &mut self,
        archive: &mut Archive,
        listing: &Listing,
        target: &Path,
        output: crate::record::Text,
        original: &Summary,
        expected: Option<&crate::record::Text>,
    ) -> Result<Stop, Stop> {
        let input = &self.path("input");
        let manifest = &self.path("manifest");
        let baseline = self.path("panic-original.bundle");
        let (panic, _, baseline_summary) =
            self.panic_run(archive, listing, manifest, &baseline, "panic-original")?;
        let identity = match panic {
            PanicVerdict::Panicked(identity) => identity,
            PanicVerdict::Passed => {
                return self.verdict("unreproduced", Sim::Complete, "the original rerun passes");
            }
            PanicVerdict::Different => {
                return self.verdict(
                    "diverged",
                    Sim::Complete,
                    "the original rerun has another failure kind",
                );
            }
        };
        let difference = self.difference(input, &baseline)?;
        if difference.is_some() || baseline_summary != *original {
            self.compared().divergence = difference;
            return self.verdict(
                "diverged",
                Sim::Complete,
                "the panic rerun differs from the frozen bundle",
            );
        }
        let failure = Failure::panic(&identity)?;
        if expected.is_some_and(|expected| expected != failure.identity()) {
            return self.verdict(
                "diverged",
                Sim::Complete,
                "the panic rerun has another identity",
            );
        }
        self.set_failure(&failure);
        let Some(reduced) = self.reduce_worker(archive, input, target)? else {
            return self.verdict(
                "unreducible",
                Sim::Complete,
                "the worker could not reduce the reproduced panic",
            );
        };
        let candidate = target.join("regression.bundle");
        let candidate_evidence =
            self.guard_bundle(&candidate, archive, listing, "candidate.manifest")?;
        self.check_reduction(&reduced, &candidate_evidence, true)?;
        self.compared().output = Some(output);
        self.compared().candidate = Some(candidate_evidence.digest);
        let candidate_summary = self.inspect_as(
            archive,
            listing,
            &candidate,
            &candidate_evidence.manifest,
            "inspect-candidate",
        )?;
        self.compared().observed = self.summary.clone();
        if candidate_summary.counts && credit(&candidate_summary, None).0 == Sim::Incomplete {
            return Err(incomplete(
                "the candidate counts a bundle without a decision",
            ));
        }
        if candidate_summary.terminal == Terminal::Infrastructure(Infrastructure::Sink) {
            return Err(incomplete("the candidate is incomplete"));
        }
        if candidate_summary.terminal.passes() {
            return self.verdict("unreproduced", Sim::Complete, "the candidate passes");
        }
        if candidate_summary.terminal != Terminal::Infrastructure(Infrastructure::Truncated) {
            return self.verdict(
                "diverged",
                Sim::Complete,
                "the candidate has another failure kind",
            );
        }
        let again = self.path("panic-candidate.bundle");
        let (observed, _, fresh_summary) = self.panic_run(
            archive,
            listing,
            &candidate_evidence.manifest,
            &again,
            "panic-candidate",
        )?;
        let difference = self.difference(&candidate, &again)?;
        self.compared().divergence = difference;
        if let PanicVerdict::Panicked(panic) = &observed {
            if reduced.panic.as_deref() != Some(panic) {
                return Err(incomplete(
                    "the reduction result differs from the candidate panic",
                ));
            }
            if fresh_summary != candidate_summary {
                return self.verdict(
                    "diverged",
                    Sim::Complete,
                    "the candidate rerun summary differs from its bundle",
                );
            }
        }
        match observed {
            PanicVerdict::Passed => {
                self.verdict("unreproduced", Sim::Complete, "the candidate rerun passes")
            }
            PanicVerdict::Different => self.verdict(
                "diverged",
                Sim::Complete,
                "the candidate rerun has another failure kind",
            ),
            PanicVerdict::Panicked(observed) if observed != identity => self.verdict(
                "diverged",
                Sim::Complete,
                "the candidate has another panic identity",
            ),
            PanicVerdict::Panicked(_) if self.compared().divergence.is_some() => self.verdict(
                "diverged",
                Sim::Complete,
                "the candidate rerun differs from its bundle",
            ),
            PanicVerdict::Panicked(_) => self.verdict(
                "reduced",
                Sim::Complete,
                &format!(
                    "reduced with equal panic identity into {}{}",
                    target.display(),
                    if reduced.bounded { " (bounded)" } else { "" },
                ),
            ),
        }
    }
    fn panic_run(
        &mut self,
        archive: &mut Archive,
        listing: &Listing,
        manifest: &Path,
        bundle: &Path,
        name: &str,
    ) -> Result<(PanicVerdict, Candidate, Summary), Stop> {
        let ran = self.phase(
            archive,
            name,
            &[
                OsStr::new("--manifest"),
                manifest.as_os_str(),
                OsStr::new("--bundle"),
                bundle.as_os_str(),
            ],
        )?;
        if ran.code == 2 {
            return Err(refused(name, "the worker refused the panic rerun"));
        }
        let candidate = self.guard_bundle(bundle, archive, listing, &format!("{name}.manifest"))?;
        let observed = self.inspect_as(
            archive,
            listing,
            bundle,
            &candidate.manifest,
            &format!("inspect-{name}"),
        )?;
        self.compared().observed = self.summary.clone();
        let verdict = match Run::parse(&ran.stdout, listing)
            .map_err(|error| incomplete(error.to_string()))?
        {
            Run::Panicked(identity) if ran.code == 3 => {
                if observed.terminal != Terminal::Infrastructure(Infrastructure::Truncated) {
                    return Err(incomplete("the panic line disagrees with the rerun bundle"));
                }
                PanicVerdict::Panicked(identity)
            }
            Run::Summary(summary) => {
                if *summary != observed {
                    return Err(incomplete(
                        "the panic rerun summary differs from its inspected bundle",
                    ));
                }
                let checked = credit(&summary, Some(ran.code));
                if matches!(summary.terminal, Terminal::Complete { .. }) {
                    if checked.0 == Sim::Incomplete {
                        return Err(checked);
                    }
                    if summary.terminal.passes() {
                        PanicVerdict::Passed
                    } else {
                        PanicVerdict::Different
                    }
                } else if ran.code == 3
                    && matches!(
                        summary.terminal,
                        Terminal::Infrastructure(Infrastructure::Cap | Infrastructure::Defect)
                    )
                {
                    PanicVerdict::Different
                } else {
                    return Err(incomplete("the panic rerun supplies incomplete evidence"));
                }
            }
            _ => return Err(incomplete("the panic rerun supplies incomplete evidence")),
        };
        Ok((verdict, candidate, observed))
    }
}
pub(super) fn read_original_bundle(
    opened: crate::store::Opened,
) -> Result<super::input::Staged, Stop> {
    let mut checked = Stager::new(opened);
    io::copy(&mut checked, &mut io::sink()).map_err(|error| incomplete(error.to_string()))?;
    if let Some(error) = checked.read_error() {
        return Err(incomplete(format!("the input source read failed: {error}")));
    }
    checked.finish().map_err(rejected)
}

fn refused(name: &str, reason: &str) -> Stop {
    if matches!(name, "candidate-replay" | "panic-candidate") {
        incomplete(reason)
    } else {
        rejected(reason)
    }
}

fn violates(summary: &Summary) -> bool {
    matches!(
        summary.terminal,
        Terminal::Complete {
            outcome: Outcome::Violation,
            ..
        }
    )
}
fn failure(summary: &Summary) -> Option<String> {
    violates(summary)
        .then(|| {
            summary
                .identity
                .as_ref()
                .map(|identity| identity.as_str().to_owned())
        })
        .flatten()
}

fn record_path(path: &Path) -> Result<crate::record::Text, Stop> {
    path.to_str()
        .and_then(crate::record::Text::new)
        .ok_or_else(|| rejected("the triage output path must be printable ASCII"))
}
fn panic_identity(identity: &str) -> crate::record::Text {
    text(
        &identity
            .chars()
            .flat_map(char::escape_default)
            .collect::<String>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_identity_escaping_keeps_distinct_payloads_distinct() {
        assert_eq!(
            panic_identity("file:1:2: \\u{e9}").as_str(),
            "file:1:2: \\\\u{e9}"
        );
        assert_eq!(panic_identity("file:1:2: é").as_str(), "file:1:2: \\u{e9}");
        assert_ne!(
            panic_identity("file:1:2: é"),
            panic_identity("file:1:2: \\u{e9}")
        );
    }
}
