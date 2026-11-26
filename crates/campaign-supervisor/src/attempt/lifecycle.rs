//! Numbered attempts bind frozen jobs to custody and classified evidence.
//! Verified histories stay contiguous within the frozen attempt limit.

use std::path::Path;

use crate::custody::{Custody, Launch as CustodyLaunch, Running, Stopped};
use crate::record::{
    Admission, Attempt as Record, BOUND, Class, Digest, Finished, Intent, Purpose, Started, Text,
    Verified,
};
use crate::store::{Creation, Dir, ReadStore, Store};

use super::binding::{self, Evidence};
use super::{BoundArtifact, Error, Launch, classify, name};

/// ```compile_fail,E0616
/// use campaign_supervisor::attempt::Attempt;
/// fn swap(a: &mut Attempt, b: &mut Attempt) {
///     std::mem::swap(&mut a.record, &mut b.record);
/// }
/// ```
pub struct Attempt {
    directory: Dir,
    record: Verified<Record>,
    job: Verified<Admission>,
}

/// A completion carries a verified finished record and an optional bound artifact.
///
/// ```compile_fail,E0616
/// use campaign_supervisor::attempt::Completed;
/// fn forge(completed: &mut Completed) {
///     completed.bound = None;
/// }
/// ```
pub struct Completed {
    finished: Verified<Finished>,
    bound: Option<Box<BoundArtifact>>,
}

impl Completed {
    pub fn finished(&self) -> &Verified<Finished> {
        &self.finished
    }
    pub(crate) fn bound(&self) -> Option<&BoundArtifact> {
        self.bound.as_deref()
    }
    pub(crate) fn has_finding(&self) -> bool {
        classify::finding_kind(self.finished.record(), self.bound()).is_some()
    }
    pub fn into_parts(self) -> (Verified<Finished>, Option<BoundArtifact>) {
        (self.finished, self.bound.map(|bound| *bound))
    }
}

pub(super) fn held_read(error: crate::store::Unreadable, reason: &'static str) -> Error {
    if error.faulted() {
        Error::Store(crate::store::Error::Unreadable(error))
    } else {
        Error::Held(reason)
    }
}

pub(crate) fn history(
    store: &impl ReadStore,
    job: &Admission,
) -> Result<Option<(Dir, u64)>, Error> {
    let Some(root) = crate::layout::attempts(store, &job.job().id().to_string())
        .map_err(|error| held_read(error, "job attempt root unreadable"))?
    else {
        return Ok(None);
    };
    let mut numbers = Vec::new();
    for entry in store.list(&root, crate::scan_bound())? {
        let number = entry
            .as_str()
            .parse::<u64>()
            .map_err(|_| Error::Held("attempt number malformed"))?;
        if number == 0
            || entry.as_str() != format!("{number:04}")
            || number > job.job().experiment().attempts
        {
            return Err(Error::Held(
                "attempt number outside canonical frozen history",
            ));
        }
        store
            .open_dir(&root, &entry)
            .map_err(|error| held_read(error, "attempt entry is not a directory"))?
            .ok_or(Error::Held("attempt entry vanished"))?;
        numbers.push(number);
    }
    numbers.sort_unstable();
    if numbers
        .iter()
        .enumerate()
        .any(|(index, number)| *number != index as u64 + 1)
    {
        return Err(Error::Held("attempt history has gaps or duplicates"));
    }
    Ok(Some((root, numbers.len() as u64)))
}

fn record(job: &Admission, number: u64, file_bytes: u64) -> Record {
    Record {
        attempt: Text::new(&format!("{}-{number:04}", job.job().id()))
            .expect("attempt identity is ASCII"),
        file_bytes,
        job: job.job().id().digest(),
        manifest: job.job().manifest_sha256(),
        number,
    }
}

/// Starts the next numbered campaign attempt after the prior finish is verified.
/// A charged prior attempt and malformed history are held. A non-campaign job,
/// exhausted limit or invalid execution input is rejected before minting.
/// Store failures return their store error. Successful launch persists the
/// attempt, reservation, intent and started records before releasing the gate.
pub fn start(
    store: &Store,
    custody: &mut Custody,
    job: Verified<Admission>,
    launch: Launch,
) -> Result<(Attempt, Running), Error> {
    start_purpose(store, custody, job, launch, Purpose::Campaign)
}

pub(crate) fn start_calibration(
    store: &Store,
    custody: &mut Custody,
    job: Verified<Admission>,
    launch: Launch,
) -> Result<(Attempt, Running), Error> {
    start_purpose(store, custody, job, launch, Purpose::Calibration)
}

fn start_purpose(
    store: &Store,
    custody: &mut Custody,
    job: Verified<Admission>,
    launch: Launch,
    purpose: Purpose,
) -> Result<(Attempt, Running), Error> {
    custody.check_release()?;
    if job.record().purpose() != purpose {
        return Err(Error::Rejected(match purpose {
            Purpose::Campaign => "only campaign jobs start numbered attempts",
            Purpose::Calibration => "only calibration jobs start calibration attempts",
        }));
    }
    store.barrier(job.read())?;
    let old = history(store, job.record())?;
    if settlement_entries(store, job.record())? {
        return Err(if old.as_ref().is_some_and(|(_, maximum)| *maximum > 0) {
            Error::Rejected("job already has a settlement entry")
        } else {
            Error::Held("settlement entry has no attempt history")
        });
    }
    let number = old.as_ref().map_or(1, |(_, number)| number + 1);
    if let Some((root, maximum)) = &old
        && *maximum > 0
    {
        let previous = load(store, job, root, *maximum)?;
        let completed = previous.read_finished(store)?;
        if number > previous.job.record().job().experiment().attempts {
            return Err(Error::Rejected("frozen attempt limit exhausted"));
        }
        if !super::settle::retryable(completed.finished().record().class) {
            return Err(Error::Rejected("finished verdict requires settlement"));
        }
        return start_after(store, custody, previous.job, launch, number);
    }
    if number > job.record().job().experiment().attempts {
        return Err(Error::Rejected("frozen attempt limit exhausted"));
    }
    start_after(store, custody, job, launch, number)
}

fn start_after(
    store: &Store,
    custody: &mut Custody,
    job: Verified<Admission>,
    launch: Launch,
    number: u64,
) -> Result<(Attempt, Running), Error> {
    let mut launch = launch;
    launch.limits = super::scaled(launch.limits, job.record().shares())?;
    let jobs = crate::layout::jobs(store, &job.record().job().id().to_string())
        .map_err(|error| held_read(error, "jobs unreadable"))?
        .ok_or(Error::Held("jobs vanished"))?;
    frozen_manifest(store, &jobs, job.record())?;
    let manifest_name = name(&format!("{}.manifest", job.record().job().id()));
    let id = job.record().job().id().to_string();
    let number_name = name(&format!("{number:04}"));
    let value = record(job.record(), number, launch.limits.file_bytes);
    let path = store.path().join(crate::layout::attempt_path(&id, number));
    let mut args = vec!["sim".into()];
    if let Some(target) = job.record().target() {
        args.extend([
            target.form.command().into(),
            store
                .path()
                .join(crate::layout::job_file(&id, &format!("{id}.bundle")))
                .into_os_string(),
            "--archive".into(),
            job.record().archive().as_str().into(),
            "--milestone".into(),
            target.milestone.as_str().into(),
        ]);
        if let crate::record::ForkForm::Branch { siblings, suffixes } = target.form {
            args.extend([
                "--suffixes".into(),
                suffixes.to_string().into(),
                "--siblings".into(),
                siblings.to_string().into(),
            ]);
        }
    } else {
        args.extend([
            "run".into(),
            "--archive".into(),
            job.record().archive().as_str().into(),
            "--manifest".into(),
            store
                .path()
                .join(crate::layout::job_file(&id, manifest_name.as_str()))
                .into_os_string(),
        ]);
    }
    args.extend([
        "--artifacts".into(),
        path.join("artifacts").into_os_string(),
        "--run-id".into(),
        value.attempt.as_str().into(),
    ]);
    let mut launch = CustodyLaunch {
        attempt: value.attempt.clone(),
        name: name(value.attempt.as_str()),
        gate: launch.gate,
        launcher: launch.launcher,
        environment: launch.environment,
        limits: launch.limits,
        directory: store.path().to_path_buf(),
        args,
    };
    launch.validate()?;
    crate::store::launch_paths(&launch.launcher, store.path()).map_err(|error| {
        let unreadable = crate::store::Unreadable::Io(error);
        if unreadable.faulted() {
            Error::Store(crate::store::Error::Unreadable(unreadable))
        } else {
            Error::Rejected("invalid attempt launcher")
        }
    })?;
    let attempts = crate::layout::make_shard(store, crate::layout::ATTEMPTS, &id)?;
    store.mkdir(&attempts, &name(&id))?;
    let root = store
        .open_dir(&attempts, &name(&id))
        .map_err(|error| held_read(error, "job attempt root unreadable"))?
        .ok_or(Error::Held("job attempt root vanished"))?;
    custody.check_release()?;
    if store.mkdir(&root, &number_name)? != Creation::Created {
        return Err(Error::Held("attempt directory already minted"));
    }
    let directory = store
        .open_dir(&root, &number_name)
        .map_err(|error| held_read(error, "attempt unreadable"))?
        .ok_or(Error::Held("minted attempt vanished"))?;
    if store.create_record(&directory, &name("attempt"), &value)? != Creation::Created {
        return Err(Error::Held("attempt record already present"));
    }
    let record = store
        .read_record::<Record>(&directory, &name("attempt"))?
        .ok_or(Error::Held("attempt record vanished"))?;
    store.barrier(record.read())?;
    if crate::custody::charge(store, &directory, &value.attempt)? != Creation::Created {
        return Err(Error::Held("attempt reservation already present"));
    }
    launch.directory = path;
    let running = custody.launch(store, &directory, launch)?;
    Ok((
        Attempt {
            directory,
            record,
            job,
        },
        running,
    ))
}

fn load(
    store: &Store,
    job: Verified<Admission>,
    root: &Dir,
    number: u64,
) -> Result<Attempt, Error> {
    let (directory, found) = read_attempt(store, job.record(), root, number)?;
    Ok(Attempt {
        directory,
        record: found,
        job,
    })
}

pub(crate) fn read_attempt(
    store: &impl ReadStore,
    job: &Admission,
    root: &Dir,
    number: u64,
) -> Result<(Dir, Verified<Record>), Error> {
    let directory = store
        .open_dir(root, &name(&format!("{number:04}")))
        .map_err(|error| held_read(error, "attempt unreadable"))?
        .ok_or(Error::Held("attempt vanished"))?;
    let found = store
        .read_record::<Record>(&directory, &name("attempt"))?
        .ok_or(Error::Held("attempt record missing"))?;
    if found.record() != &record(job, number, found.record().file_bytes) {
        return Err(Error::Held("attempt identity differs from frozen job"));
    }
    Ok((directory, found))
}

impl Attempt {
    pub fn current(store: &Store, job: Verified<Admission>) -> Result<Option<Self>, Error> {
        let Some((root, maximum)) = history(store, job.record())? else {
            return Ok(None);
        };
        if maximum == 0 {
            return Ok(None);
        }
        load(store, job, &root, maximum).map(Some)
    }

    pub fn identity(&self) -> &Text {
        &self.record.record().attempt
    }
    pub fn number(&self) -> u64 {
        self.record.record().number
    }

    pub(crate) fn reservation(&self, store: &Store) -> Result<bool, Error> {
        Ok(crate::custody::charged(store, &self.directory, self.identity())?.is_some())
    }

    pub(crate) fn output(&self) -> u64 {
        self.record.record().file_bytes
    }

    pub(super) fn current_token(&self, store: &Store) -> Result<(), Error> {
        let Some((_, maximum)) = history(store, self.job.record())? else {
            return Err(Error::Held("attempt history vanished"));
        };
        if maximum != self.number() {
            return Err(Error::Held("attempt is not the current publish token"));
        }
        store.barrier(self.job.read())?;
        store.barrier(self.record.read())?;
        Ok(())
    }

    pub fn finish(
        self,
        store: &Store,
        stopped: Stopped,
        evidence_bound: usize,
    ) -> Result<Completed, Error> {
        self.execution().finish(store, stopped, evidence_bound)
    }
    pub fn read_finished(&self, store: &Store) -> Result<Completed, Error> {
        self.execution().read_finished(store)
    }
    pub fn reconcile(
        self,
        store: &Store,
        custody: &mut Custody,
        evidence_bound: usize,
    ) -> Result<Completed, Error> {
        self.execution().reconcile(store, custody, evidence_bound)
    }
    fn execution(&self) -> Execution<'_> {
        Execution {
            directory: &self.directory,
            record: self.record.record(),
            command: self.job.record().command(),
            publisher: self,
        }
    }
}

/// Publishers barrier the durable token before checking that it is still current.
pub(crate) trait Publisher {
    fn current_token(&self, store: &Store) -> Result<(), Error>;
    fn read_token(&self, store: &Store) -> Result<(), Error> {
        self.current_token(store)
    }
}
impl Publisher for Attempt {
    fn current_token(&self, store: &Store) -> Result<(), Error> {
        self.current_token(store)
    }
}

pub(crate) struct Execution<'a> {
    pub directory: &'a Dir,
    pub record: &'a Record,
    pub command: &'a str,
    pub publisher: &'a dyn Publisher,
}
impl Execution<'_> {
    fn identity(&self) -> &Text {
        &self.record.attempt
    }
    pub fn finish(
        self,
        store: &Store,
        stopped: Stopped,
        evidence_bound: usize,
    ) -> Result<Completed, Error> {
        self.publisher.current_token(store)?;
        if stopped.identity() != self.identity() {
            return Err(Error::Held("stopped tree names another attempt"));
        }
        let started = store.read_record::<Started>(self.directory, &name("started"))?;
        if stopped.started().is_some_and(|proof| {
            started
                .as_ref()
                .is_none_or(|found| found.record() != proof.record())
        }) {
            return Err(Error::Held("started record differs from stopped proof"));
        }
        if let Some(started) = &started {
            store.barrier(started.read())?;
        }
        let tree = stopped.evidence(store, self.directory, evidence_bound)?;
        let evidence = binding::read_command(store, tree.directory(), self.record, self.command)?;
        let mut finished = tree.stopped().finished(
            Class::Incomplete,
            evidence.state(),
            evidence.binding().cloned(),
        )?;
        finished.class = classify::classify(&finished, &evidence);
        if let Some(bound) = &finished.bound {
            store.create_record(tree.directory(), &name("bound"), bound)?;
            let found = store
                .read_record::<crate::record::BoundEvidence>(tree.directory(), &name("bound"))?
                .ok_or(Error::Held("bound record vanished"))?;
            if found.record() != bound {
                return Err(Error::Held("bound record differs"));
            }
            store.barrier(found.read())?;
        }
        self.publisher.current_token(store)?;
        let finished = tree.complete(store, &finished)?;
        Ok(Completed {
            finished,
            bound: evidence.into_bound(),
        })
    }

    pub fn read_finished(&self, store: &Store) -> Result<Completed, Error> {
        self.publisher.read_token(store)?;
        read_completed(store, self.directory, self.record, self.command)
    }

    pub fn reconcile(
        self,
        store: &Store,
        custody: &mut Custody,
        evidence_bound: usize,
    ) -> Result<Completed, Error> {
        self.publisher.read_token(store)?;
        let charged = crate::custody::charged(store, self.directory, self.identity())
            .map(|value| value.is_some());
        if matches!(&charged, Ok(false)) {
            match self.read_finished(store) {
                Ok(completed) => return Ok(completed),
                Err(Error::Held("attempt is unfinished")) => {}
                Err(error) => return Err(error),
            }
        }
        self.publisher.current_token(store)?;
        let existing = store.read_record::<Finished>(self.directory, &name("finished"))?;
        if store
            .read_record::<Intent>(self.directory, &name("intent"))?
            .is_none()
        {
            if !matches!(&charged, Ok(true)) {
                return charged.and(Err(Error::Held("pending attempt lacks reservation")));
            }
            custody.pending(store, self.directory, self.identity())?;
        }
        let (intent, started) = witnesses(
            store,
            self.directory,
            self.record,
            existing
                .as_ref()
                .is_some_and(|record| record.record().class == Class::Pass),
        )?;
        let stopped = custody.reconcile(store, &intent, started.as_ref())?;
        charged?;
        if let Some(finished) = existing {
            let tree = stopped.evidence(store, self.directory, evidence_bound)?;
            let evidence = validate_finished(
                store,
                tree.directory(),
                self.record,
                &finished,
                self.command,
            )?;
            self.publisher.current_token(store)?;
            let finished = tree.complete(store, finished.record())?;
            return Ok(Completed {
                finished,
                bound: evidence.into_bound(),
            });
        }
        self.finish(store, stopped, evidence_bound)
    }
}

fn validate_finished(
    store: &impl ReadStore,
    directory: &Dir,
    record: &Record,
    verified: &Verified<Finished>,
    command: &str,
) -> Result<Evidence, Error> {
    let finished = verified.record();
    if finished.attempt != record.attempt {
        return Err(Error::Held("finished names another attempt"));
    }
    let evidence = match store
        .read_record::<crate::record::Reclaimed>(directory, &name("reclaimed"))?
    {
        Some(marker) => {
            if marker.record().attempt != record.number
                || marker.record().finished != crate::record::Digest::of(verified.read().bytes())
            {
                return Err(Error::Held("reclaim record names another finish"));
            }
            store.barrier(marker.read())?;
            let bound = finished
                .bound
                .as_ref()
                .ok_or(Error::Held("reclaimed attempt lacks bound evidence"))?;
            binding::reclaimed(store, directory, record, bound, command)?
        }
        None => binding::read_command(store, directory, record, command)?,
    };
    let observed = evidence.binding();
    if evidence.state() != finished.binding
        || observed != finished.bound.as_ref()
        || classify::classify(finished, &evidence) != finished.class
    {
        return Err(Error::Held("stored outcome differs from bound evidence"));
    }
    if let Some(observed) = observed {
        let bound = store
            .read_record::<crate::record::BoundEvidence>(directory, &name("bound"))?
            .ok_or(Error::Held("finished lacks bound record"))?;
        if bound.record() != observed {
            return Err(Error::Held("stored binding differs"));
        }
        store.barrier(bound.read())?;
    }
    Ok(evidence)
}

/// Settlement checks the current publisher separately.
pub(crate) fn completed_at(
    store: &impl ReadStore,
    job: &Admission,
    root: &Dir,
    number: u64,
) -> Result<(Dir, Verified<Record>, Completed), Error> {
    let (directory, record) = read_attempt(store, job, root, number)?;
    store.barrier(record.read())?;
    let completed = read_completed(store, &directory, record.record(), job.command())?;
    Ok((directory, record, completed))
}

pub(super) fn prior_finish(
    store: &Store,
    job: &Admission,
    root: &Dir,
    number: u64,
) -> Result<(Dir, Verified<Finished>), Error> {
    let (directory, record) = read_attempt(store, job, root, number)?;
    let finished = store
        .read_record::<Finished>(&directory, &name("finished"))?
        .ok_or(Error::Held("attempt is unfinished"))?;
    if finished.record().attempt != record.record().attempt {
        return Err(Error::Held("finished names another attempt"));
    }
    Ok((directory, finished))
}

pub(crate) fn read_completed(
    store: &impl ReadStore,
    directory: &Dir,
    record: &Record,
    command: &str,
) -> Result<Completed, Error> {
    let finished = store
        .read_record::<Finished>(directory, &name("finished"))?
        .ok_or(Error::Held("attempt is unfinished"))?;
    let (intent, _) = witnesses(
        store,
        directory,
        record,
        finished.record().class == Class::Pass,
    )?;
    if crate::store::cgroup_present(Path::new(intent.record().cgroup.as_str()))? {
        return Err(Error::Held("finished tree remains present"));
    }
    if crate::custody::charged(store, directory, &record.attempt)?.is_some() {
        return Err(Error::Held("finished attempt remains charged"));
    }
    let evidence = validate_finished(store, directory, record, &finished, command)?;
    store.barrier(finished.read())?;
    Ok(Completed {
        finished,
        bound: evidence.into_bound(),
    })
}

fn witnesses(
    store: &impl ReadStore,
    directory: &Dir,
    record: &Record,
    pass: bool,
) -> Result<(Verified<Intent>, Option<Verified<Started>>), Error> {
    let intent = store
        .read_record::<Intent>(directory, &name("intent"))?
        .ok_or(Error::Held("attempt lacks intent"))?;
    if intent.record().attempt != record.attempt {
        return Err(Error::Held("intent names another attempt"));
    }
    let started = store.read_record::<Started>(directory, &name("started"))?;
    if pass && started.is_none() {
        return Err(Error::Held("pass lacks started witness"));
    }
    if let Some(started) = &started {
        if !started.record().agrees_with(intent.record()) {
            return Err(Error::Held("started differs from intent"));
        }
        store.barrier(started.read())?;
    }
    store.barrier(intent.read())?;
    Ok((intent, started))
}

pub(crate) fn frozen_manifest(
    store: &impl ReadStore,
    jobs: &Dir,
    job: &Admission,
) -> Result<(), Error> {
    let manifest_name = name(&format!("{}.manifest", job.job().id()));
    let manifest = store
        .read(jobs, &manifest_name, BOUND)
        .map_err(|error| held_read(error, "frozen manifest unreadable"))?
        .ok_or(Error::Held("frozen manifest vanished"))?;
    if Digest::of(manifest.bytes()) != job.job().manifest_sha256() {
        return Err(Error::Held("frozen manifest digest differs"));
    }
    store.barrier(&manifest)?;
    if let Some(target) = job.target() {
        let entry = name(&format!("{}.bundle", job.job().id()));
        if store
            .evidence_digest(jobs, &entry, target.bytes)
            .map_err(|error| held_read(error, "frozen target unreadable"))?
            != Some(target.bundle)
        {
            return Err(Error::Held("frozen target bundle differs"));
        }
        let file = store
            .open_file(jobs, &entry)
            .map_err(|error| held_read(error, "frozen target unreadable"))?
            .ok_or(Error::Held("frozen target vanished"))?;
        store.sync_file(jobs, &file)?;
    }
    Ok(())
}

pub(crate) fn settlement_entries(store: &impl ReadStore, job: &Admission) -> Result<bool, Error> {
    let id = job.job().id().digest();
    let jobs = crate::layout::jobs(store, &id.to_string())
        .map_err(|error| Error::Store(error.into()))?
        .ok_or(Error::Held("jobs directory vanished"))?;
    let pin = store.read_record::<crate::record::Pin>(
        &jobs,
        &name(&format!("{id}{}", crate::record::Pin::SUFFIX)),
    )?;
    let result = store.read_record::<crate::record::JobResult>(
        &jobs,
        &name(&format!("{id}{}", crate::record::JobResult::SUFFIX)),
    )?;
    for entry in pin
        .as_ref()
        .map(|pin| &pin.record().result)
        .into_iter()
        .chain(result.as_ref().map(|result| result.record()))
    {
        if entry.job != id || entry.manifest != job.job().manifest_sha256() {
            return Err(Error::Held("settlement entry differs from frozen job"));
        }
    }
    if let Some(pin) = &pin {
        store.barrier(pin.read())?;
    }
    if let Some(result) = &result {
        store.barrier(result.read())?;
    }
    Ok(pin.is_some() || result.is_some())
}

pub(crate) fn queued_target(store: &impl ReadStore, job: &Admission) -> Result<bool, Error> {
    if job.target().is_none() {
        return Ok(false);
    }
    let empty = history(store, job)?.is_none_or(|(_, maximum)| maximum == 0);
    Ok(empty && !settlement_entries(store, job)?)
}

/// Verifies present custody witnesses and returns whether a started record exists.
pub(crate) fn pending_started(
    store: &impl ReadStore,
    directory: &Dir,
    record: &Record,
) -> Result<bool, Error> {
    let intent = store.read_record::<Intent>(directory, &name("intent"))?;
    let started = store.read_record::<Started>(directory, &name("started"))?;
    if let Some(intent) = &intent {
        if intent.record().attempt != record.attempt {
            return Err(Error::Held("intent names another attempt"));
        }
        store.barrier(intent.read())?;
    }
    if let Some(started) = &started {
        let intent = intent
            .as_ref()
            .ok_or(Error::Held("started attempt lacks intent"))?;
        if started.record().attempt != record.attempt
            || !started.record().agrees_with(intent.record())
        {
            return Err(Error::Held("started witness binding differs"));
        }
        store.barrier(started.read())?;
    }
    crate::custody::charged(store, directory, &record.attempt)?;
    Ok(started.is_some())
}
