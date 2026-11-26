use super::{Error, contract, directory, execution, name, text};
use crate::attempt::{Execution, Publisher};
use crate::custody::Custody;
use crate::record::{CalibrationEvidence, CalibrationPlan, CalibrationReplay, Digest, Verified};
use crate::store::{Dir, ReadStore, Store};
use std::path::Path;

struct Replay {
    directory: Dir,
    plan: Verified<CalibrationPlan>,
    record: Verified<CalibrationReplay>,
}

fn root(store: &impl ReadStore, plan: &CalibrationPlan) -> Result<Option<Dir>, Error> {
    let directory = directory(store, plan.healthy.job().id().digest())?;
    Ok(store.open_dir(&directory, &name("replays"))?)
}

fn source(plan: &CalibrationPlan, store: &impl ReadStore) -> std::path::PathBuf {
    let id = plan.healthy.job().id();
    store
        .path()
        .join(crate::layout::attempt_path(&id.to_string(), 2))
        .join("artifacts")
        .join(format!("{id}-0002"))
}

fn load(
    store: &impl ReadStore,
    plan: Verified<CalibrationPlan>,
    number: u64,
) -> Result<Replay, Error> {
    if !(1..=2).contains(&number) {
        return Err(Error::Held(
            "calibration replay number is outside 1..=2".into(),
        ));
    }
    let parent = root(store, plan.record())?
        .ok_or_else(|| Error::Held("calibration replay root missing".into()))?;
    let directory = store
        .open_dir(&parent, &name(&format!("{number:04}")))?
        .ok_or_else(|| Error::Held("calibration replay missing".into()))?;
    let record = store
        .read_record::<CalibrationReplay>(&directory, &name("replay"))?
        .ok_or_else(|| Error::Held("calibration replay record missing".into()))?;
    let job = plan.record().healthy.job();
    let attempt = &record.record().attempt;
    if attempt.job != job.id().digest()
        || attempt.manifest != job.manifest_sha256()
        || attempt.number != number
        || attempt.attempt.as_str() != format!("{}-calibration-replay-{number:04}", job.id())
        || attempt.file_bytes != plan.record().config.file_bytes()
        || crate::store::lexical(Path::new(record.record().source.as_str()))
            != canonical_source(&source(plan.record(), store))?
    {
        return Err(Error::Held("calibration replay binding differs".into()));
    }
    store.barrier(record.read())?;
    store.barrier(plan.read())?;
    Ok(Replay {
        directory,
        plan,
        record,
    })
}

impl Replay {
    fn capture(&self, store: &Store, completed: &crate::attempt::Completed) -> Result<(), Error> {
        super::super::once(
            store,
            &self.directory,
            "attempt",
            &self.record.record().attempt,
        )?;
        let attempt = store
            .read_record::<crate::record::Attempt>(&self.directory, &name("attempt"))?
            .ok_or_else(|| Error::Held("calibration replay attempt missing".into()))?;
        crate::attempt::capture(
            store,
            &self.plan.record().healthy,
            completed,
            &self.directory,
            &attempt,
            Some(self.plan.record().healthy.job().id().digest()),
        )?;
        Ok(())
    }
    fn execution(&self) -> Execution<'_> {
        Execution {
            directory: &self.directory,
            record: &self.record.record().attempt,
            command: "replay",
            publisher: self,
        }
    }
}
impl Publisher for Replay {
    fn current_token(&self, store: &Store) -> Result<(), crate::custody::Error> {
        store.barrier(self.plan.read())?;
        store.barrier(self.record.read())?;
        Ok(())
    }
}

pub(crate) fn reconcile(
    store: &Store,
    custody: &mut Custody,
) -> Result<std::collections::BTreeMap<String, String>, Error> {
    let mut held = std::collections::BTreeMap::new();
    let Some(roots) = store.open_dir(store.root(), &name("calibrations"))? else {
        return Ok(held);
    };
    for entry in store.list(&roots, crate::scan_bound())? {
        let directory = match store.open_dir(&roots, &entry) {
            Ok(Some(directory)) => directory,
            Ok(None) => continue,
            Err(error) if !error.faulted() => {
                held.insert(entry.as_str().to_owned(), Error::from(error).to_string());
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = reconcile_root(store, custody, &directory, entry.as_str()) {
            if super::super::triage::global(&error)
                || custodial_records(store, custody, &roots, &directory, entry.as_str())?
            {
                return Err(if error.at_scan_bound() {
                    error
                } else {
                    Error::Custody(error.to_string())
                });
            }
            held.insert(entry.as_str().to_owned(), error.to_string());
        }
    }
    Ok(held)
}

fn claimed_jobs(store: &Store, roots: &Dir) -> Result<std::collections::BTreeSet<String>, Error> {
    let mut claimed = std::collections::BTreeSet::new();
    for entry in store.list(roots, crate::scan_bound())? {
        let directory = match store.open_dir(roots, &entry) {
            Ok(Some(directory)) => directory,
            Ok(None) => continue,
            Err(error) if !error.faulted() => continue,
            Err(error) => return Err(error.into()),
        };
        let plan = match store.read_record::<CalibrationPlan>(&directory, &name("plan")) {
            Ok(Some(plan)) => plan,
            Ok(None) => continue,
            Err(crate::record::Held::Unreadable(error)) if error.faulted() => {
                return Err(crate::record::Held::Unreadable(error).into());
            }
            Err(_) => continue,
        };
        claimed.insert(plan.record().healthy.job().id().to_string());
        claimed.extend(
            plan.record()
                .controls
                .values()
                .map(|job| job.job().id().to_string()),
        );
    }
    Ok(claimed)
}

/// Custody attributed to root `id` is its replays, its healthy job and, with a
/// readable plan, its controls. A root whose plan is missing or unreadable is
/// charged with every calibration job that no readable plan claims, since any
/// of them may be its control.
fn custodial_records(
    store: &Store,
    custody: &Custody,
    roots: &Dir,
    directory: &Dir,
    id: &str,
) -> Result<bool, Error> {
    let mut parents = Vec::new();
    if let Some(replays) = store.open_dir(directory, &name("replays"))? {
        parents.push(replays);
    }
    if store.open_dir(store.root(), &name("attempts"))?.is_some() {
        let mut jobs = vec![id.to_owned()];
        match store.read_record::<CalibrationPlan>(directory, &name("plan")) {
            Ok(Some(plan)) => jobs.extend(
                plan.record()
                    .controls
                    .values()
                    .map(|job| job.job().id().to_string()),
            ),
            _ => {
                let claimed = claimed_jobs(store, roots)?;
                for shard in crate::campaign::sharded(store, crate::layout::JOBS)? {
                    let shard = shard?;
                    let admissions = &shard.dir;
                    for entry in super::super::shard_entries(store, &shard)? {
                        if entry
                            .as_str()
                            .strip_suffix(".json")
                            .and_then(Digest::parse)
                            .is_none()
                        {
                            continue;
                        }
                        let admission = store
                            .read_record::<crate::record::Admission>(admissions, &entry)?
                            .ok_or_else(|| Error::Held("calibration admission missing".into()))?;
                        let job = admission.record().job().id().to_string();
                        if admission.record().purpose() == crate::record::Purpose::Calibration
                            && !claimed.contains(&job)
                        {
                            jobs.push(job);
                        }
                    }
                }
            }
        }
        for id in jobs {
            if let Some(attempts) = crate::layout::attempts(store, &id)? {
                parents.push(attempts);
            }
        }
    }
    for parent in parents {
        for entry in store.list(&parent, crate::scan_bound())? {
            let directory = store
                .open_dir(&parent, &entry)?
                .ok_or_else(|| Error::Held("calibration custody directory missing".into()))?;
            if let Some(intent) =
                store.read_record::<crate::record::Intent>(&directory, &name("intent"))?
                && !custody.inactive(intent.record()).map_err(Error::custody)?
            {
                return Ok(true);
            }
            if store.open_file(&directory, &name("reservation"))?.is_some()
                || store.open_file(&directory, &name("intent"))?.is_some()
                    && store
                        .read_record::<crate::record::Finished>(&directory, &name("finished"))?
                        .is_none()
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn reconcile_root(
    store: &Store,
    custody: &mut Custody,
    directory: &Dir,
    id: &str,
) -> Result<(), Error> {
    let Some(plan) = store.read_record::<CalibrationPlan>(directory, &name("plan"))? else {
        if store.list(directory, crate::scan_bound())?.is_empty() {
            return Ok(());
        }
        return Err(Error::Held("calibration plan missing".into()));
    };
    if id != plan.record().healthy.job().id().to_string() {
        return Err(Error::Held("calibration plan root differs".into()));
    }
    store.barrier(plan.read())?;
    if let Some(result) =
        store.read_record::<crate::record::Calibration>(directory, &name("result"))?
    {
        if result.record().root != plan.record().healthy.job().id().digest()
            || result.record().contract != contract(plan.record())?
        {
            return Err(Error::Held("calibration result binding differs".into()));
        }
        store.barrier(result.read())?;
    }
    let Some(replays) = store.open_dir(directory, &name("replays"))? else {
        return Ok(());
    };
    for entry in store.list(&replays, crate::scan_bound())? {
        let number = entry
            .as_str()
            .parse::<u64>()
            .map_err(|_| Error::Held("calibration replay number malformed".into()))?;
        if entry.as_str() != format!("{number:04}") {
            return Err(Error::Held(
                "calibration replay number is noncanonical".into(),
            ));
        }
        let plan = store
            .read_record::<CalibrationPlan>(directory, &name("plan"))?
            .expect("calibration plan verified");
        let target = store
            .open_dir(&replays, &entry)?
            .ok_or_else(|| Error::Held("calibration replay directory missing".into()))?;
        if store
            .read_record::<CalibrationReplay>(&target, &name("replay"))?
            .is_none()
            && store.list(&target, crate::scan_bound())?.is_empty()
        {
            continue;
        }
        let replay = load(store, plan, number)?;
        let reserved = crate::custody::charged(
            store,
            &replay.directory,
            &replay.record.record().attempt.attempt,
        )
        .map_err(Error::custody)?
        .is_some();
        let intent =
            store.read_record::<crate::record::Intent>(&replay.directory, &name("intent"))?;
        if reserved || intent.is_some() {
            let completed = replay
                .execution()
                .reconcile(store, custody, crate::attempt::EVIDENCE_BOUND)
                .map_err(Error::custody)?;
            replay.capture(store, &completed)?;
            execution::evidence(
                store,
                &replay.directory,
                &completed,
                replay.record.record().attempt.job,
                None,
            )?;
        } else if store
            .read_record::<crate::record::Started>(&replay.directory, &name("started"))?
            .is_some()
        {
            return Err(Error::Held(
                "calibration replay started without intent".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn execute(
    store: &Store,
    custody: &mut Custody,
    plan: &CalibrationPlan,
    original: &CalibrationEvidence,
    number: u64,
    executable: &Path,
) -> Result<CalibrationEvidence, Error> {
    let original_artifact = original
        .artifact
        .as_ref()
        .ok_or_else(|| Error::Held("original calibration artifact missing".into()))?;
    let mut archive = crate::archive::Archive::load(Path::new(plan.healthy.archive().as_str()))
        .map_err(|error| {
            if error.exit(false) == crate::exit::Sim::Rejected {
                Error::Rejected(error.to_string())
            } else {
                Error::Held(error.to_string())
            }
        })?;
    if archive.id() != contract(plan)?.build {
        return Err(Error::Held("calibration archive changed".into()));
    }
    archive
        .verify()
        .and_then(|approved| approved.finish().map_err(|error| error.0))
        .map_err(|error| {
            if error.exit(false) == crate::exit::Sim::Rejected {
                Error::Rejected(error.to_string())
            } else {
                Error::Held(error.to_string())
            }
        })?;
    let directory = directory(store, plan.healthy.job().id().digest())?;
    store.mkdir(&directory, &name("replays"))?;
    let replays = store
        .open_dir(&directory, &name("replays"))?
        .expect("replay root created");
    store.mkdir(&replays, &name(&format!("{number:04}")))?;
    let target = store
        .open_dir(&replays, &name(&format!("{number:04}")))?
        .expect("replay directory created");
    let record = CalibrationReplay {
        attempt: crate::record::Attempt {
            attempt: text(&format!(
                "{}-calibration-replay-{number:04}",
                plan.healthy.job().id()
            ))?,
            file_bytes: plan.config.file_bytes(),
            job: plan.healthy.job().id().digest(),
            manifest: plan.healthy.job().manifest_sha256(),
            number,
        },
        original: Digest::of(
            &serde_json::to_vec(original_artifact).expect("original artifact encodes"),
        ),
        source: text(
            source(plan, store)
                .to_str()
                .ok_or_else(|| Error::Held("replay source must be ASCII".into()))?,
        )?,
    };
    match store.read_record::<CalibrationReplay>(&target, &name("replay"))? {
        None => {
            store.create_record(&target, &name("replay"), &record)?;
        }
        Some(found) => {
            if found.record().attempt != record.attempt
                || found.record().original != record.original
            {
                return Err(Error::Held("record publication differs".into()));
            }
            store.barrier(found.read())?;
        }
    }
    let found = store
        .read_record::<CalibrationPlan>(&directory, &name("plan"))?
        .expect("plan is present");
    let replay = load(store, found, number)?;
    let intent = store.read_record::<crate::record::Intent>(&replay.directory, &name("intent"))?;
    if intent.is_some() {
        let completed = replay
            .execution()
            .reconcile(store, custody, crate::attempt::EVIDENCE_BOUND)
            .map_err(Error::custody)?;
        replay.capture(store, &completed)?;
        return execution::evidence(
            store,
            &replay.directory,
            &completed,
            record.attempt.job,
            None,
        );
    }
    let path = store
        .path()
        .join("calibrations")
        .join(plan.healthy.job().id().to_string())
        .join("replays")
        .join(format!("{number:04}"));
    let launch = crate::custody::Launch {
        attempt: record.attempt.attempt.clone(),
        name: name(record.attempt.attempt.as_str()),
        gate: executable.into(),
        launcher: executable.into(),
        directory: path.clone(),
        environment: Default::default(),
        limits: super::super::configuration::limits(&plan.config),
        args: vec![
            "sim".into(),
            "replay".into(),
            "--from-run".into(),
            record.source.as_str().into(),
            "--artifacts".into(),
            path.join("artifacts").into_os_string(),
            "--run-id".into(),
            record.attempt.attempt.as_str().into(),
            "--watchdog".into(),
            plan.config.value("wall").to_string().into(),
        ],
    };
    launch.validate()?;
    crate::store::launch_paths(&launch.launcher, store.path()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidInput {
            Error::Rejected(error.to_string())
        } else {
            Error::Store(crate::store::Error::Io(error))
        }
    })?;
    custody.check_release()?;
    execution::capacity(store, custody, &plan.config)?;
    crate::custody::charge(store, &replay.directory, &record.attempt.attempt)?;
    let running = custody.launch(store, &replay.directory, launch)?;
    let (stopped, wait_error) = execution::wait(custody, running)?;
    let elapsed = stopped
        .elapsed_ms()
        .and_then(|value| value.checked_mul(1000));
    let completed = replay
        .execution()
        .finish(store, stopped, crate::attempt::EVIDENCE_BOUND)?;
    replay.capture(store, &completed)?;
    let evidence = execution::evidence(
        store,
        &replay.directory,
        &completed,
        record.attempt.job,
        elapsed,
    )?;
    match wait_error {
        Some(error) => Err(error.into()),
        None => Ok(evidence),
    }
}

pub(in crate::campaign) fn partial(
    store: &impl ReadStore,
    plan: &CalibrationPlan,
) -> Result<Vec<CalibrationEvidence>, Error> {
    let Some(root) = root(store, plan)? else {
        return Ok(Vec::new());
    };
    let directory = directory(store, plan.healthy.job().id().digest())?;
    let mut evidence = Vec::new();
    for entry in store.list(&root, crate::scan_bound())? {
        let number = entry
            .as_str()
            .parse::<u64>()
            .map_err(|_| Error::Held("calibration replay number malformed".into()))?;
        if entry.as_str() != format!("{number:04}") || !(1..=2).contains(&number) {
            return Err(Error::Held(
                "calibration replay number is noncanonical".into(),
            ));
        }
        let found = store
            .read_record::<CalibrationPlan>(&directory, &name("plan"))?
            .ok_or_else(|| Error::Held("calibration plan missing".into()))?;
        let target = store
            .open_dir(&root, &entry)?
            .ok_or_else(|| Error::Held("calibration replay directory missing".into()))?;
        if store
            .read_record::<CalibrationReplay>(&target, &name("replay"))?
            .is_none()
            && store.list(&target, crate::scan_bound())?.is_empty()
        {
            continue;
        }
        let intent = store.read_record::<crate::record::Intent>(&target, &name("intent"))?;
        let charge =
            store.read_record::<crate::record::Reservation>(&target, &name("reservation"))?;
        if intent.is_none()
            && charge.is_none()
            && store
                .read_record::<crate::record::Started>(&target, &name("started"))?
                .is_none()
        {
            continue;
        }
        let (_, completed) = verified_completion(store, found, number)?;
        evidence.push(execution::snapshot(
            &completed,
            plan.healthy.job().id().digest(),
        ));
    }
    Ok(evidence)
}

pub(in crate::campaign) fn verified_completion(
    store: &impl ReadStore,
    plan: Verified<CalibrationPlan>,
    number: u64,
) -> Result<(Dir, crate::attempt::Completed), Error> {
    let replay = load(store, plan, number)?;
    let completed = crate::attempt::read_completed(
        store,
        &replay.directory,
        &replay.record.record().attempt,
        "replay",
    )?;
    Ok((replay.directory, completed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    #[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
    fn quiescent_damaged_roots_are_held_while_recovery_continues() {
        let _processes = crate::store::fixture::processes();
        let host = crate::custody::run_tests::Hosted::new(25010);
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody(Duration::from_secs(1));
        store.mkdir(store.root(), &name("calibrations")).unwrap();
        let roots = store
            .open_dir(store.root(), &name("calibrations"))
            .unwrap()
            .unwrap();
        let id = Digest::of(b"held-root").to_string();
        store.mkdir(&roots, &name(&id)).unwrap();
        let root = store.open_dir(&roots, &name(&id)).unwrap().unwrap();
        store.create_once(&root, &name("plan"), b"damaged").unwrap();
        let held = reconcile(&store, &mut custody).unwrap();
        assert!(held.contains_key(&id));
        store.mkdir(store.root(), &name("attempts")).unwrap();
        let jobs = crate::layout::make_shard(&store, crate::layout::JOBS, &id).unwrap();
        store
            .create_once(
                &jobs,
                &name(&format!("{id}.result.json")),
                b"unread-as-admission",
            )
            .unwrap();
        assert!(reconcile(&store, &mut custody).unwrap().contains_key(&id));
        store
            .delete(&jobs, &name(&format!("{id}.result.json")))
            .unwrap();
        super::super::super::dispatch::recover(&store, &mut custody).unwrap();
        let view = crate::store::View::open(store.path()).unwrap();
        let rows = super::super::status::status(&view).unwrap();
        assert_eq!(rows[0]["verdict"], "held");
        let report = crate::campaign::report::project(&view).unwrap();
        assert!(
            report["calibrations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| {
                    row["id"] == id && row["verdict"] == "held" && row["qualified"] == false
                })
        );
        assert!(
            report["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| { row["path"] == format!("calibrations/{id}") })
        );
        let scoped = crate::record::CalibrationContract {
            build: Digest::of(b"build"),
            profile: text("upload").unwrap(),
            counts: Default::default(),
        };
        assert!(super::super::eligible(&store, &scoped).is_err());
    }

    #[test]
    #[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
    fn a_non_directory_calibration_entry_is_held_while_recovery_continues() {
        // A regular file named like a root holds no custody records, so it is
        // one held row and recovery of everything else continues.
        let _processes = crate::store::fixture::processes();
        let host = crate::custody::run_tests::Hosted::new(25012);
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody(Duration::from_secs(1));
        store.mkdir(store.root(), &name("calibrations")).unwrap();
        let roots = store
            .open_dir(store.root(), &name("calibrations"))
            .unwrap()
            .unwrap();
        let id = Digest::of(b"file-root").to_string();
        store
            .create_once(&roots, &name(&id), b"not a directory")
            .unwrap();
        let held = reconcile(&store, &mut custody).unwrap();
        assert_eq!(held.keys().collect::<Vec<_>>(), [&id]);
        super::super::super::dispatch::recover(&store, &mut custody).unwrap();
    }

    #[test]
    #[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
    fn a_damaged_plan_holds_only_on_unclaimed_calibration_custody() {
        // A root whose plan is unreadable holds on charged custody of
        // calibration jobs that no readable plan claims. A reservation under
        // another root's healthy job belongs to that root.
        let _processes = crate::store::fixture::processes();
        let host = crate::custody::run_tests::Hosted::new(25013);
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody(Duration::from_secs(1));
        let listing = crate::protocol::Listing::parse(include_str!(
            "../../../testdata/admission-listing.txt"
        ))
        .unwrap();
        let digest = text(&Digest::of(b"build").to_string()).unwrap();
        let pins = crate::record::Pins {
            build: digest.clone(),
            executable: digest,
            platform: text("x86_64").unwrap(),
            toolchain: text("rustc").unwrap(),
        };
        let admit = |run: u64| {
            super::super::super::admit(
                &store,
                &listing,
                pins.clone(),
                text("/archive").unwrap(),
                &super::super::super::Request {
                    profile: text("upload").unwrap(),
                    campaign: text("calibration").unwrap(),
                    run,
                    attempts: 2,
                    counts: std::collections::BTreeMap::new(),
                },
                crate::record::Purpose::Calibration,
            )
            .unwrap()
            .record
        };
        let charge = |admission: &crate::record::Admission| {
            let id = admission.job().id().to_string();
            let attempts = crate::layout::make_shard(&store, crate::layout::ATTEMPTS, &id).unwrap();
            store.mkdir(&attempts, &name(&id)).unwrap();
            let job = store.open_dir(&attempts, &name(&id)).unwrap().unwrap();
            store.mkdir(&job, &name("0001")).unwrap();
            let attempt = store.open_dir(&job, &name("0001")).unwrap().unwrap();
            crate::custody::charge(&store, &attempt, &text(&format!("{id}-0001")).unwrap())
                .unwrap();
        };
        store.mkdir(store.root(), &name("calibrations")).unwrap();
        let roots = store
            .open_dir(store.root(), &name("calibrations"))
            .unwrap()
            .unwrap();
        let damaged = Digest::of(b"damaged-plan").to_string();
        store.mkdir(&roots, &name(&damaged)).unwrap();
        let root = store.open_dir(&roots, &name(&damaged)).unwrap().unwrap();
        store.create_once(&root, &name("plan"), b"damaged").unwrap();
        let claimed = admit(0);
        let plan = CalibrationPlan {
            config: super::super::tests::config(),
            controls: std::collections::BTreeMap::new(),
            deduplicated: true,
            healthy: claimed.clone(),
            missing: Vec::new(),
        };
        let id = claimed.job().id().to_string();
        store.mkdir(&roots, &name(&id)).unwrap();
        let root = store.open_dir(&roots, &name(&id)).unwrap().unwrap();
        store.create_record(&root, &name("plan"), &plan).unwrap();
        charge(&claimed);
        let held = reconcile(&store, &mut custody).unwrap();
        assert_eq!(held.keys().collect::<Vec<_>>(), [&damaged]);
        charge(&admit(1));
        assert!(matches!(
            reconcile(&store, &mut custody),
            Err(Error::Custody(_))
        ));
    }

    #[test]
    #[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
    fn damaged_roots_with_charged_replays_hold_recovery() {
        let _processes = crate::store::fixture::processes();
        let host = crate::custody::run_tests::Hosted::new(25011);
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody(Duration::from_secs(1));
        store.mkdir(store.root(), &name("calibrations")).unwrap();
        let roots = store
            .open_dir(store.root(), &name("calibrations"))
            .unwrap()
            .unwrap();
        let id = Digest::of(b"charged-root").to_string();
        store.mkdir(&roots, &name(&id)).unwrap();
        let root = store.open_dir(&roots, &name(&id)).unwrap().unwrap();
        store.create_once(&root, &name("plan"), b"damaged").unwrap();
        store.mkdir(&root, &name("replays")).unwrap();
        let replays = store.open_dir(&root, &name("replays")).unwrap().unwrap();
        store.mkdir(&replays, &name("0001")).unwrap();
        let replay = store.open_dir(&replays, &name("0001")).unwrap().unwrap();
        crate::custody::charge(
            &store,
            &replay,
            &text(&format!("{id}-replay-0001")).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            reconcile(&store, &mut custody),
            Err(Error::Custody(_))
        ));
        assert!(super::super::super::dispatch::recover(&store, &mut custody).is_err());
        assert!(
            store
                .open_file(&replay, &name("reservation"))
                .unwrap()
                .is_some()
        );
    }
}

fn canonical_source(path: &Path) -> Result<std::path::PathBuf, Error> {
    crate::store::canonical_host(path).map_err(|error| {
        let error = crate::store::Unreadable::from(error);
        if error.faulted() {
            Error::Store(crate::store::Error::Unreadable(error))
        } else {
            Error::Held(format!("calibration replay source unavailable: {error}"))
        }
    })
}

#[cfg(test)]
#[path = "replay_source_tests.rs"]
mod source_error_tests;
