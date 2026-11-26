//! Triage reserves custody before execution and seals results after the tree drains.

use super::{Error, Step, candidate, history, name, text, verdict};
use crate::attempt::{Completed, Execution, Launch};
use crate::custody::{Custody, Stopped};
use crate::record::{
    Artifact, Attempt, Configuration, Digest, Finding, ReplayDependencies, StepKind, TriageResult,
    TriageStep,
};
use crate::store::{Creation, Dir, ReadStore, Store};
use std::io::Read;
use std::path::Path;

pub(crate) fn controller_limit() -> Result<u64, Error> {
    let hard = crate::sys::controller_file_limit().map_err(crate::store::Error::Io)?;
    if hard < crate::record::BOUND {
        return Err(Error::Custody(
            "controller RLIMIT_FSIZE is below the triage record bound".into(),
        ));
    }
    Ok(hard)
}

use super::super::once;

pub(super) fn dependencies(finding: &Finding) -> Result<ReplayDependencies, Error> {
    Ok(ReplayDependencies {
        archive: Digest::parse(finding.admission.job().experiment().pins.build.as_str())
            .ok_or_else(|| Error::Held("finding archive digest invalid".into()))?,
        archive_path: finding.admission.archive().clone(),
        bundle: finding.bundle(),
        finding: finding.id(),
        manifest: finding.attempt.manifest,
    })
}

#[cfg(test)]
pub(crate) fn start(
    store: &Store,
    custody: &mut Custody,
    request: super::Request<'_>,
    config: &Configuration,
    launch: Launch,
    committed_output: u64,
) -> Result<(Step, crate::custody::Running), Error> {
    admit(
        store,
        custody,
        request,
        config,
        launch,
        Occupancy {
            census: &mut None,
            steps: 0,
            committed_output,
            running: &mut [],
        },
    )?
    .started()
}

pub(crate) struct Occupancy<'a> {
    /// The session census the storage decision and input staging charge,
    /// counted at the storage decision when the slot holds none and kept in
    /// it for the caller's later decisions.
    pub(crate) census: &'a mut Option<crate::campaign::census::Census>,
    pub(crate) committed_output: u64,
    /// Running triage trees that already occupy the reserved slots.
    pub(crate) steps: usize,
    pub(crate) running: &'a mut [crate::custody::Running],
}

pub(crate) fn admit(
    store: &Store,
    custody: &mut Custody,
    request: super::Request<'_>,
    config: &Configuration,
    launch: Launch,
    occupancy: Occupancy<'_>,
) -> Result<super::Admission, Error> {
    let super::Request {
        id,
        kind,
        archive: alternate,
    } = request;
    let Occupancy {
        census,
        committed_output,
        steps,
        running,
    } = occupancy;
    let supervise = |custody: &mut Custody, running: &mut [crate::custody::Running]| {
        custody.supervise(running).map_err(Error::custody)
    };
    supervise(custody, running)?;
    if history::reserved(store)? >= config.value("reserve_slots") {
        return Ok(super::Admission::Pause(
            ["triage reserve slots".to_owned()].into(),
        ));
    }
    if launch.limits != super::super::configuration::limits(config) {
        return Err(Error::Rejected(
            "triage launch limits differ from configuration".into(),
        ));
    }
    controller_limit()?;
    text(
        store
            .path()
            .to_str()
            .ok_or_else(|| Error::Rejected("state path must be printable ASCII".into()))?,
    )?;
    let finding = history::finding(store, id)?;
    supervise(custody, running)?;
    let deps = dependencies(finding.record())?;
    if let Some(reason) = finding.record().bundle_wait_reason() {
        return Ok(super::Admission::Skip(reason.into()));
    }
    if finding.record().admission.target().is_some() && kind == StepKind::Rerun {
        return Ok(super::Admission::Skip(
            "targeted findings replay their retained bundle".into(),
        ));
    }
    if let Some(path) = alternate {
        let archive = match crate::archive::Archive::load(path) {
            Ok(archive) => archive,
            Err(error) => return archive_refusal(error),
        };
        if archive.id() != deps.archive {
            return Ok(super::Admission::Skip(
                "another build cannot triage this finding".into(),
            ));
        }
    }
    let mut archive = match crate::archive::Archive::load(Path::new(deps.archive_path.as_str())) {
        Ok(archive) => archive,
        Err(error) => return archive_refusal(error),
    };
    if archive.id() != deps.archive {
        return Ok(super::Admission::Skip(
            "original archive identity differs".into(),
        ));
    }
    let old = history::summaries(store, id, finding.record())?;
    if !(finding.record().admission.target().is_some() && kind == StepKind::Replay)
        && history::stalled(&old, config, kind)
    {
        return Ok(super::Admission::Skip(format!(
            "triage stalled under these limits: class={} output_limited={} file_limited={} attempt_output={} attempt_inodes={}",
            old.last()
                .map(|(_, result)| result.finished.class.name())
                .unwrap_or("unmeasured"),
            old.last().is_some_and(|(_, result)| result.output_limited),
            old.last().is_some_and(|(_, result)| result.file_limited),
            config.value("attempt_output"),
            config.value("attempt_inodes")
        )));
    }
    if kind == StepKind::Replay && deps.bundle.is_none() {
        return Ok(super::Admission::Skip(
            "triage step needs a retained bundle".into(),
        ));
    }
    if kind == StepKind::Reduce
        && let Some(reason) = verdict::reduction(store, finding.record())?
    {
        return Ok(super::Admission::Skip(reason.into()));
    }
    let retained = retained(store, id)?;
    let inputs = crate::attempt::dependencies(finding.record())
        .map_err(|error| Error::Held(error.to_string()))?;
    let mut input_bytes = 0u64;
    let hard = controller_limit()?;
    for (entry, _, _) in &inputs {
        let file = store
            .open_file(&retained, entry)?
            .ok_or_else(|| Error::Held("retained dependency missing".into()))?;
        if file.len() > hard {
            return Ok(super::Admission::Skip(
                "triage input exceeds controller RLIMIT_FSIZE".into(),
            ));
        }
        input_bytes = input_bytes.saturating_add(file.len());
    }
    if input_bytes > config.file_bytes() {
        return Ok(super::Admission::Skip(
            "retained inputs exceed triage output budget".into(),
        ));
    }
    let fixed_inodes = 12u64.saturating_add(inputs.len() as u64);
    if config.value("attempt_inodes").saturating_add(fixed_inodes)
        > crate::attempt::EVIDENCE_BOUND as u64
    {
        return Ok(super::Admission::Skip(
            "triage evidence needs additional inode headroom".into(),
        ));
    }
    let charged = committed_output.div_ceil(config.file_bytes());
    let usage = crate::campaign::census::Census::cached(census, store)?.usage(store, config)?;
    let paused = super::super::dispatch::storage_pauses(config, usage, charged, 0);
    if !paused.is_empty() {
        return Ok(super::Admission::Pause(paused));
    }
    supervise(custody, running)?;
    if let Err(error) = archive.verify().map(drop) {
        return archive_refusal(error);
    }
    supervise(custody, running)?;
    super::super::dispatch::fit_or_stop(custody, launch.limits, config, running, steps)?;
    custody.set_watchdog(config.value("wall"))?;
    let number = old.len() as u64 + 1;
    if number > crate::scan_bound() as u64 {
        return Err(Error::bound(&format!("triage/{id}/steps"), number as usize));
    }
    let attempt = Attempt {
        attempt: text(&format!("{id}-triage-{number:04}"))?,
        file_bytes: config.file_bytes(),
        job: finding.record().attempt.job,
        manifest: deps.manifest,
        number,
    };
    let path = history::step_path(store, id, number);
    let source = path.join(id);
    let mut args = vec!["sim".into(), kind.command().into()];
    if finding.record().admission.target().is_some() {
        args.extend([
            source.join("bundle").into_os_string(),
            "--archive".into(),
            deps.archive_path.as_str().into(),
        ]);
        if kind == StepKind::Reduce {
            args.extend(["--output".into(), path.join("reduced").into_os_string()]);
        }
    } else {
        match kind {
            StepKind::Replay => {
                args.extend(["--from-run".into(), source.clone().into_os_string()]);
            }
            StepKind::Rerun => {
                args.extend([
                    "--archive".into(),
                    deps.archive_path.as_str().into(),
                    "--manifest".into(),
                    source.join("manifest").into_os_string(),
                ]);
            }
            StepKind::Reduce => {
                args.extend([
                    "--from-run".into(),
                    source.clone().into_os_string(),
                    "--output".into(),
                    path.join("reduced").into_os_string(),
                ]);
            }
        }
    }
    args.extend([
        "--artifacts".into(),
        path.join("artifacts").into_os_string(),
        "--run-id".into(),
        attempt.attempt.as_str().into(),
        "--watchdog".into(),
        config.value("wall").to_string().into(),
    ]);
    let launcher_path = text(
        launch
            .launcher
            .to_str()
            .ok_or_else(|| Error::Rejected("launcher path is not ASCII".into()))?,
    )?;
    let mut custody_launch = crate::custody::Launch {
        attempt: attempt.attempt.clone(),
        name: name(attempt.attempt.as_str()),
        gate: launch.gate,
        launcher: launch.launcher,
        environment: launch.environment,
        limits: launch.limits,
        directory: store.path().to_path_buf(),
        args,
    };
    custody_launch.validate()?;
    crate::store::launch_paths(&custody_launch.launcher, store.path()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidInput {
            Error::Rejected(error.to_string())
        } else {
            Error::Store(crate::store::Error::Io(error))
        }
    })?;
    if let Err(error) = custody.check_release() {
        if error.draining() {
            return Ok(super::Admission::Drain(None));
        }
        return Err(error.into());
    }
    let mut directory = None;
    for component in ["triage", id, "steps"] {
        let parent = directory.as_ref().unwrap_or_else(|| store.root());
        store.mkdir(parent, &name(component))?;
        directory = Some(
            store
                .open_dir(parent, &name(component))?
                .ok_or_else(|| Error::Held("triage root vanished".into()))?,
        );
    }
    let root = directory.expect("triage path has three components");
    let entry = name(&format!("{number:04}"));
    if store.mkdir(&root, &entry)? != Creation::Created {
        return Err(Error::Held("triage number already minted".into()));
    }
    let directory = store
        .open_dir(&root, &entry)?
        .ok_or_else(|| Error::Held("triage directory vanished".into()))?;
    once(
        store,
        &directory,
        "step",
        &TriageStep {
            attempt,
            finding: text(id)?,
            kind,
            launcher: launcher_path,
            limits: config.config().clone(),
        },
    )?;
    let step = history::pending(store, &root, finding, number)?;
    step.stage_inputs(store, census)?;
    supervise(custody, running)?;
    crate::custody::charge(store, &step.directory, step.identity())?;
    custody_launch.directory = path;
    match custody.launch(store, &step.directory, custody_launch) {
        Ok(running) => Ok(super::Admission::Started(Box::new((step, running)))),
        Err(error) if error.draining() => Ok(super::Admission::Drain(Some(Box::new(
            step.reconcile(store, custody)?,
        )))),
        Err(error) => Err(Error::custody(error)),
    }
}

pub(super) fn retained(store: &impl ReadStore, id: &str) -> Result<Dir, Error> {
    let root = store
        .open_dir(store.root(), &name("findings"))?
        .ok_or_else(|| Error::Held("finding root vanished".into()))?;
    store
        .open_dir(&root, &name(id))?
        .ok_or_else(|| Error::Held("finding vanished".into()))
}

impl Step {
    /// Copies the finding's retained inputs into the step after checking
    /// their bytes and inodes against the usage of the census in `census`
    /// and the measured free space. The census is counted into the slot at
    /// that check when the slot holds none, after every refusal that needs
    /// no census.
    pub(super) fn stage_inputs(
        &self,
        store: &Store,
        census: &mut Option<crate::campaign::census::Census>,
    ) -> Result<(), Error> {
        let directory = &self.directory;
        let id = self.finding_id();
        let finding = &self.finding;
        let deps = dependencies(finding.record())?;
        store.mkdir(directory, &name(id))?;
        let source = store
            .open_dir(directory, &name(id))?
            .ok_or_else(|| Error::Held("replay source vanished".into()))?;
        let retained = retained(store, id)?;
        let hard = controller_limit()?;
        let files = crate::attempt::dependencies(finding.record())?;
        let mut remaining = 0u64;
        let mut inodes = 0u64;
        let mut total = 0u64;
        for (entry, _, _) in &files {
            let file = store
                .open_file(&retained, entry)?
                .ok_or_else(|| Error::Held("retained dependency missing".into()))?;
            if file.len() > hard {
                return Err(Error::Held(
                    "triage copy exceeds controller RLIMIT_FSIZE".into(),
                ));
            }
            total = total.saturating_add(file.len());
            if store.open_file(&source, entry)?.is_none() {
                remaining = remaining.saturating_add(file.len());
                inodes += 1;
            }
        }
        if total > self.record.record().attempt.file_bytes {
            return Err(Error::Held(
                "retained inputs exceed frozen triage output budget".into(),
            ));
        }
        let config = store
            .read_record::<Configuration>(store.root(), &name("config.json"))?
            .ok_or_else(|| Error::Held("triage configuration missing".into()))?;
        let usage = crate::campaign::census::Census::cached(census, store)?
            .usage(store, config.record())?;
        if usage.bytes.saturating_add(remaining) >= config.record().value("artifact_bytes")
            || u128::from(usage.free_bytes)
                <= (crate::record::Charge {
                    bytes: u128::from(remaining),
                    inodes: u128::from(inodes),
                })
                .disk(usage.fragment_bytes)
            || usage.inodes.saturating_add(inodes) >= config.record().value("artifact_inodes")
            || usage.free_inodes <= inodes
        {
            return Err(Error::Held(
                "triage input staging exceeds storage budget".into(),
            ));
        }
        for (entry, digest, bound) in crate::attempt::dependencies(finding.record())? {
            let file = store
                .open_file(&retained, &entry)?
                .ok_or_else(|| Error::Held("retained dependency vanished".into()))?;
            if file.len() > hard {
                return Err(Error::Held(
                    "triage copy exceeds controller RLIMIT_FSIZE".into(),
                ));
            }
            if store.evidence_digest(&source, &entry, bound)?.is_none() {
                store.copy_once(
                    &source,
                    &entry,
                    &mut file.take(bound.saturating_add(1)),
                    0o600,
                )?;
            }
            let copied = store
                .open_file(&source, &entry)?
                .ok_or_else(|| Error::Held("copied dependency missing".into()))?;
            store.sync_file(&source, &copied)?;
            if store.evidence_digest(&source, &entry, bound)? != Some(digest) {
                return Err(Error::Held("copied dependency differs".into()));
            }
        }
        if let Some(artifact) = &finding.record().artifact {
            let mut artifact = artifact.clone();
            artifact.archive_path = Some(deps.archive_path.clone());
            once(store, &source, "artifact", &artifact)?;
        }
        once(store, directory, "dependencies", &deps)?;
        Ok(())
    }

    pub fn identity(&self) -> &crate::record::Text {
        &self.record.record().attempt.attempt
    }
    pub(crate) fn finding_id(&self) -> &str {
        self.record.record().finding.as_str()
    }
    pub(super) fn execution(&self) -> Execution<'_> {
        Execution {
            directory: &self.directory,
            record: &self.record.record().attempt,
            command: self.record.record().kind.command(),
            publisher: self,
        }
    }
    pub(super) fn dependencies(&self, store: &impl ReadStore) -> Result<ReplayDependencies, Error> {
        let found = store
            .read_record::<ReplayDependencies>(&self.directory, &name("dependencies"))?
            .ok_or_else(|| Error::Held("step lacks replay dependencies".into()))?;
        let expected = dependencies(self.finding.record())?;
        if found.record() != &expected {
            return Err(Error::Held("step dependencies differ".into()));
        }
        store.barrier(found.read())?;
        let source = store
            .open_dir(&self.directory, &name(self.finding_id()))?
            .ok_or_else(|| Error::Held("step source missing".into()))?;
        for (entry, digest, bound) in crate::attempt::dependencies(self.finding.record())? {
            let copied = store
                .open_file(&source, &entry)?
                .ok_or_else(|| Error::Held("copied dependency missing".into()))?;
            store.sync_file(&source, &copied)?;
            if store.evidence_digest(&source, &entry, bound)? != Some(digest) {
                return Err(Error::Held("step source differs".into()));
            }
        }
        if let Some(expected) = &self.finding.record().artifact {
            let mut expected = expected.clone();
            expected.archive_path = Some(found.record().archive_path.clone());
            let artifact = store
                .read_record::<Artifact>(&source, &name("artifact"))?
                .ok_or_else(|| Error::Held("step source artifact missing".into()))?;
            if artifact.record() != &expected {
                return Err(Error::Held("step source artifact differs".into()));
            }
            store.barrier(artifact.read())?;
        }
        Ok(expected)
    }
    pub(crate) fn reconcile(
        self,
        store: &Store,
        custody: &mut Custody,
    ) -> Result<TriageResult, Error> {
        let completed = self
            .execution()
            .reconcile(store, custody, crate::attempt::EVIDENCE_BOUND)
            .map_err(Error::custody)?;
        self.conclude(store, completed, None)
    }
    pub fn finish(self, store: &Store, stopped: Stopped) -> Result<TriageResult, Error> {
        let elapsed = stopped.elapsed_ms();
        let completed = self
            .execution()
            .finish(store, stopped, crate::attempt::EVIDENCE_BOUND)
            .map_err(Error::custody)?;
        self.conclude(store, completed, elapsed)
    }
    pub(super) fn read_result(
        &self,
        store: &Store,
        completed: &Completed,
    ) -> Result<TriageResult, Error> {
        let expected = self.verified_result(store, completed)?;
        candidate::verify(store, self, &expected, completed)?;
        Ok(expected)
    }
    pub(super) fn verified_result(
        &self,
        store: &impl ReadStore,
        completed: &Completed,
    ) -> Result<TriageResult, Error> {
        let result = store
            .read_record::<TriageResult>(&self.directory, &name("result"))?
            .ok_or_else(|| Error::Held("step result missing".into()))?;
        let expected = verdict::judge(store, self, completed, result.record().elapsed_ms)?;
        if result.record() != &expected {
            return Err(Error::Held("step result differs from evidence".into()));
        }
        store.barrier(result.read())?;
        Ok(expected)
    }
    pub(super) fn conclude(
        &self,
        store: &Store,
        completed: Completed,
        elapsed: Option<u64>,
    ) -> Result<TriageResult, Error> {
        if store
            .read_record::<TriageResult>(&self.directory, &name("result"))?
            .is_some()
        {
            let result = self.read_result(store, &completed)?;
            candidate::write(store, self, &result, &completed)?;
            return Ok(result);
        }
        let result = verdict::judge(store, self, &completed, elapsed)?;
        once(store, &self.directory, "result", &result)?;
        candidate::write(store, self, &result, &completed)?;
        Ok(result)
    }
}

pub fn execute(
    store: &Store,
    custody: &mut Custody,
    id: &str,
    kind: StepKind,
    alternate: Option<&Path>,
    config: &Configuration,
    launch: Launch,
) -> Result<Outcome, Error> {
    controller_limit()?;
    let mut census = None;
    let reconciled = history::reconcile_counted(store, custody, &mut census);
    let recovered = super::super::dispatch::recover_counted(store, custody, &mut census);
    if let Some(reason) = reconciled?.remove(id) {
        recovered?;
        return Err(Error::Held(reason));
    }
    recovered?;
    let admission = admit(
        store,
        custody,
        super::Request {
            id,
            kind,
            archive: alternate,
        },
        config,
        launch,
        Occupancy {
            census: &mut census,
            steps: 0,
            committed_output: 0,
            running: &mut [],
        },
    )?;
    let (step, running) = match admission {
        Admission::Started(pair) => *pair,
        Admission::Drain(Some(result)) => return Ok(Outcome::Finished(result)),
        Admission::Drain(None) => return Ok(Outcome::Drained(text(id)?)),
        Admission::Pause(reasons) => {
            return Err(Error::Rejected(format!(
                "triage reservation paused: {}",
                reasons.into_iter().collect::<Vec<_>>().join(", ")
            )));
        }
        Admission::Skip(reason) => return Err(Error::Rejected(reason)),
    };
    let waited = match custody.wait_any(vec![running]) {
        Ok(waited) => waited,
        Err(error) => {
            if !custody.resource_faulted(step.identity())
                && custody.held_identity() != Some(step.identity())
                && let Some(running) = custody
                    .take_retained()
                    .into_iter()
                    .find(|running| running.started().record().attempt == *step.identity())
            {
                step.finish(store, custody.stop(running)?)?;
            }
            return Err(error.into());
        }
    };
    step.finish(store, waited.stopped)
        .map(|result| Outcome::Finished(Box::new(result)))
}

impl crate::attempt::Publisher for Step {
    fn read_token(&self, store: &Store) -> Result<(), crate::custody::Error> {
        store.barrier(self.record.read())?;
        store.barrier(self.finding.read())?;
        Ok(())
    }
    fn current_token(&self, store: &Store) -> Result<(), crate::custody::Error> {
        let map = |error| match error {
            Error::Store(error) => crate::custody::Error::Store(error),
            Error::Unreadable(error) => {
                crate::custody::Error::Store(crate::store::Error::Unreadable(error))
            }
            Error::Record(error) => crate::custody::Error::from(error),
            Error::Bound {
                root,
                entries,
                bound,
            } => crate::custody::Error::Bound {
                root,
                entries,
                bound,
            },
            _ => crate::custody::Error::Held("triage publish token differs"),
        };
        let id = self.finding_id();
        let root = history::root(store, id)
            .map_err(map)?
            .ok_or(crate::custody::Error::Held("triage history missing"))?;
        if history::numbers(store, &root, id)
            .map_err(map)?
            .last()
            .copied()
            != Some(self.record.record().attempt.number)
        {
            return Err(crate::custody::Error::Held("triage publish token is stale"));
        }
        store.barrier(self.record.read())?;
        store.barrier(self.finding.read())?;
        Ok(())
    }
}

fn archive_refusal(error: crate::archive::Invalid) -> Result<super::Admission, Error> {
    if error.exit(false) == crate::exit::Sim::Rejected {
        Ok(super::Admission::Skip(error.to_string()))
    } else {
        Err(Error::Held(error.to_string()))
    }
}

pub struct Request<'a> {
    pub id: &'a str,
    pub kind: crate::record::StepKind,
    pub archive: Option<&'a std::path::Path>,
}

pub enum Admission {
    Started(Box<(Step, crate::custody::Running)>),
    Drain(Option<Box<TriageResult>>),
    Pause(std::collections::BTreeSet<String>),
    Skip(String),
}
impl Admission {
    #[cfg(test)]
    fn started(self) -> Result<(Step, crate::custody::Running), Error> {
        match self {
            Self::Started(pair) => Ok(*pair),
            Self::Drain(_) => Err(Error::Held("triage admission drained".into())),
            Self::Pause(reasons) => Err(Error::Rejected(format!(
                "triage reservation paused: {}",
                reasons.into_iter().collect::<Vec<_>>().join(", ")
            ))),
            Self::Skip(reason) => Err(Error::Rejected(reason)),
        }
    }
}

#[derive(Debug)]
pub enum Outcome {
    Finished(Box<TriageResult>),
    Drained(crate::record::Text),
}
impl Outcome {
    pub fn value(self) -> serde_json::Value {
        match self {
            Self::Finished(result) => serde_json::to_value(result).expect("triage result encodes"),
            Self::Drained(finding) => {
                serde_json::json!({"finding":finding,"started":false,"state":"drained","status":null})
            }
        }
    }
}
