use super::{Catalog, Error, directory, name, once, reconcile, retained_bytes, text, verify};
use crate::archive::Archive;
use crate::custody::{Custody, Launch, Timing};
use crate::record::{
    BOUND, Configuration, CorpusAsset, CorpusProbe, CorpusVersion, Digest, ProbeFinished,
    ProbeOutcome, Record,
};
use crate::store::{Creation, Store};
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::time::Duration;

#[cfg(test)]
pub(super) fn publish(
    store: &Store,
    asset: &CorpusAsset,
    config: &Configuration,
) -> Result<u64, Error> {
    let dir = publication_directory(store, asset, config)?;
    register(store, &dir, asset)
}

pub(super) fn publication_directory(
    store: &Store,
    asset: &CorpusAsset,
    config: &Configuration,
) -> Result<crate::store::Dir, Error> {
    let probe = super::probe_directory(store, &asset.probe)?;
    super::super::probe::released(store, &probe, &asset.probe.attempt)?;
    if verify::stored_result(store, &probe, &asset.probe)? != *asset {
        return Err(Error::Held(
            "corpus publication differs from verified probe".into(),
        ));
    }
    let catalog = Catalog::load(store)?;
    if catalog
        .assets
        .values()
        .any(|row| row.asset.id() == asset.id() || row.asset.semantic_key() == asset.semantic_key())
    {
        return Err(Error::Rejected(
            "duplicate corpus identity or semantic state".into(),
        ));
    }
    let active = catalog.active();
    let change_versions = 2u128;
    if active >= config.value("corpus_count") {
        return Err(Error::Rejected("corpus count limit reached".into()));
    }
    if u128::from(catalog.version) + u128::from(active) + change_versions
        > crate::scan_bound() as u128
    {
        return Err(Error::Held(Error::authority_full("corpus version")));
    }
    let id = asset.id();
    let additional = u128::from(probe.usage(crate::scan_bound())?.bytes)
        + asset.encoded_len() as u128
        + u128::from(super::history::retirement_reserve(id))
        + (CorpusVersion {
            asset: id,
            number: u64::MAX,
            retired: false,
        }
        .encoded_len() as u128);
    if u128::from(retained_bytes(store, &catalog)?) + additional
        > u128::from(config.value("corpus_bytes"))
    {
        return Err(Error::Rejected("corpus byte limit reached".into()));
    }
    let corpus = directory(store, store.root(), "corpus")?;
    let assets = directory(store, &corpus, "assets")?;
    let entry = id.to_string();
    let history = store.list(&assets, crate::scan_bound())?;
    if history.len() >= crate::scan_bound() && !history.iter().any(|name| name.as_str() == entry) {
        return Err(Error::Held(Error::authority_full("corpus asset")));
    }
    directory(store, &assets, &entry)
}

pub(super) fn register(
    store: &Store,
    dir: &crate::store::Dir,
    asset: &CorpusAsset,
) -> Result<u64, Error> {
    once(store, dir, "asset", asset)?;
    Ok(reconcile(store)?.version)
}

pub(super) fn uninterrupted(signal: Option<i32>) -> Result<(), Error> {
    match signal {
        None => Ok(()),
        Some(_) => Err(Error::Held("corpus publication interrupted".into())),
    }
}

pub(super) fn judged(
    result: Result<CorpusAsset, Error>,
    interruption: Option<i32>,
) -> Result<CorpusAsset, Error> {
    uninterrupted(interruption)?;
    result
}

pub(in crate::campaign) fn add(
    store: &Store,
    archive_path: &Path,
    bundle: &Path,
    milestone: &str,
    root: &Path,
) -> Result<(CorpusAsset, u64), Error> {
    if milestone.is_empty() || milestone.starts_with("recovery-") {
        return Err(Error::Rejected(
            "corpus requires a non-recovery milestone".into(),
        ));
    }
    let milestone = text(milestone)?;
    let config = store
        .read_record::<Configuration>(store.root(), &name("config.json"))?
        .ok_or_else(|| {
            Error::Rejected("corpus requires configured count and byte limits".into())
        })?;
    if config.record().value("corpus_count") == 0 {
        return Err(Error::Rejected(
            "corpus requires configured count and byte limits".into(),
        ));
    }
    store.barrier(config.read())?;
    let config = config.record();
    let mut archive = Archive::load(archive_path).map_err(archive_error)?;
    archive
        .verify()
        .and_then(|approved| approved.finish().map_err(|error| error.0))
        .map_err(archive_error)?;
    let mut custody = Custody::open(
        root,
        Timing {
            poll: Duration::from_millis(10),
            kill_wait: Duration::from_secs(5),
            watchdog: Duration::from_secs(config.value("wall")),
        },
    )?;
    super::super::probe::reconcile_records(store, &mut custody)?;
    let mut census = None;
    super::super::triage::reconcile_counted(store, &mut custody, &mut census)?;
    super::super::dispatch::recover_counted(store, &mut custody, &mut census)?;
    if custody.interruption()?.is_some() {
        return Err(Error::Held("controller interruption requires drain".into()));
    }
    let catalog = reconcile(store)?;
    if catalog.active() >= config.value("corpus_count") {
        return Err(Error::Rejected("corpus count limit reached".into()));
    }
    let paused = super::super::dispatch::storage_pauses(
        config,
        crate::campaign::census::Census::cached(&mut census, store)?.usage(store, config)?,
        0,
        config.value("reserve_slots"),
    );
    if !paused.is_empty() {
        return Err(Error::Rejected(format!(
            "corpus probe capacity: {}",
            paused.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    let remaining = config
        .value("corpus_bytes")
        .saturating_sub(retained_bytes(store, &catalog)?);
    let hard = crate::sys::controller_file_limit().map_err(crate::store::Error::Io)?;
    if hard < BOUND {
        return Err(Error::Rejected(
            "corpus controller RLIMIT_FSIZE cannot hold records".into(),
        ));
    }
    let input_bound = config
        .file_bytes()
        .min(remaining)
        .min(hard.saturating_sub(1));
    if input_bound == 0 {
        return Err(Error::Rejected(
            "corpus byte limit leaves insufficient probe capacity".into(),
        ));
    }
    let limits = super::super::configuration::limits(config);
    super::super::dispatch::ancestor_fit(&custody, limits, config)?;
    let (id, dir, staged) = stage(store, bundle, input_bound)?;
    let charge = crate::sim::branch_probe_charge(staged.bytes);
    if charge.bytes > u128::from(config.file_bytes())
        || charge.inodes > u128::from(config.value("attempt_inodes"))
    {
        return Err(Error::Rejected("corpus probe attempt_output or attempt_inodes cannot hold two bundle copies, branch streams and controller records".into()));
    }
    let values = crate::sim::input::Values::parse(&staged.manifest, "corpus bundle")
        .map_err(Error::Rejected)?;
    values
        .pinned(&archive.pins(), "corpus bundle")
        .map_err(Error::Rejected)?;
    store.create_once(&dir, &name("manifest"), staged.manifest.as_bytes())?;
    let probe = CorpusProbe {
        archive: archive.id(),
        archive_path: text(
            archive
                .path()
                .to_str()
                .ok_or_else(|| Error::Rejected("corpus archive path must be ASCII".into()))?,
        )?,
        attempt: id.clone(),
        bundle: staged.digest,
        bytes: staged.bytes,
        manifest: Digest::of(staged.manifest.as_bytes()),
        milestone,
    };
    if catalog.assets.values().any(|row| {
        row.asset.probe.bundle == probe.bundle && row.asset.probe.milestone == probe.milestone
    }) {
        return Err(Error::Rejected(
            "duplicate corpus bundle and milestone".into(),
        ));
    }
    once(store, &dir, "corpus-probe", &probe)?;
    crate::custody::charge(store, &dir, &id)?;
    let path = store.path().join("probes").join(id.as_str());
    let executable = crate::store::canonical_host(Path::new("/proc/self/exe"))
        .map_err(|e| Error::Held(e.to_string()))?;
    let running = custody.launch(
        store,
        &dir,
        Launch {
            attempt: id.clone(),
            name: name(id.as_str()),
            gate: executable.clone(),
            launcher: executable,
            directory: path.clone(),
            environment: Default::default(),
            limits,
            args: vec![
                "sim".into(),
                "branch".into(),
                path.join("bundle").into(),
                "--archive".into(),
                archive.path().into(),
                "--milestone".into(),
                probe.milestone.as_str().into(),
                "--suffixes".into(),
                "1".into(),
                "--siblings".into(),
                "1".into(),
                "--output".into(),
                path.join("branch").into(),
                "--artifacts".into(),
                path.join("artifacts").into(),
                "--run-id".into(),
                id.as_str().into(),
                "--watchdog".into(),
                config.value("wall").to_string().into(),
            ],
        },
    )?;
    let stopped = custody.wait_any(vec![running])?.stopped;
    let code = stopped.status().and_then(|status| status.code());
    let judgement = stop_judgement(
        crate::attempt::classify_stopped(&stopped),
        custody.interruption(),
        (
            stopped.interruption(),
            stopped.status().and_then(|status| status.signal()),
        ),
        stopped.watchdog(),
        code,
    );
    let (outcome, result) = match judgement {
        Err((outcome, error)) => (outcome, Err(error)),
        Ok(()) => {
            let result = verify::result(store, &dir, &probe, code).and_then(|asset| {
                uninterrupted(custody.interruption()?)?;
                Ok(asset)
            });
            (
                if result.is_ok() {
                    ProbeOutcome::Complete
                } else {
                    ProbeOutcome::Held
                },
                result,
            )
        }
    };
    super::super::probe::release(
        store,
        &dir,
        stopped,
        &ProbeFinished {
            attempt: id,
            outcome,
        },
    )?;
    let asset = judged(result, custody.interruption()?)?;
    let dir = publication_directory(store, &asset, config)?;
    // The final signal poll is the publication cutoff; register completes the durable commit.
    uninterrupted(custody.interruption()?)?;
    let version = register(store, &dir, &asset)?;
    Ok((asset, version))
}

pub(super) fn stop_judgement(
    classification: Result<(crate::record::Class, Vec<&'static str>, bool), crate::custody::Error>,
    interruption: Result<Option<i32>, crate::custody::Error>,
    signals: (Option<i32>, Option<i32>),
    watchdog: bool,
    code: Option<i32>,
) -> Result<(), (ProbeOutcome, Error)> {
    let held = |error: crate::custody::Error| (ProbeOutcome::Held, Error::from(error));
    let (class, limits, residual_members) = classification.map_err(held)?;
    let controller = interruption.map_err(held)?;
    probe_judgement(
        class,
        &limits,
        (controller.or(signals.0), signals.1),
        watchdog,
        code,
        residual_members,
    )
}

pub(super) fn probe_judgement(
    class: crate::record::Class,
    limits: &[&str],
    signals: (Option<i32>, Option<i32>),
    watchdog: bool,
    code: Option<i32>,
    residual_members: bool,
) -> Result<(), (ProbeOutcome, Error)> {
    use crate::record::Class;
    let (signal, launcher_signal) = signals;
    if watchdog
        || matches!(code, Some(5 | 6))
        || launcher_signal.is_some_and(|signal| crate::sys::STOP_SIGNALS.contains(&(signal as u64)))
        || (launcher_signal == Some(crate::sys::OUTPUT_SIGNAL) && class != Class::OutputLimit)
        || signal.is_some_and(|signal| {
            let output_limit = signal == crate::sys::OUTPUT_SIGNAL && class == Class::OutputLimit;
            let cpu_limit = signal == crate::sys::CPU_SIGNAL
                && matches!(class, Class::CpuLimit | Class::MixedLimits);
            !(output_limit || cpu_limit)
        })
    {
        return Err((
            ProbeOutcome::Held,
            Error::Held(format!(
                "corpus probe interrupted or timed out ({})",
                class.name()
            )),
        ));
    }
    let mixed = limits.join(", ");
    let limit = match class {
        Class::OutputLimit => Some((
            ProbeOutcome::OutputLimit,
            "attempt_output or attempt_inodes",
        )),
        Class::Oom => Some((ProbeOutcome::Oom, "tree_memory")),
        Class::PidLimit => Some((ProbeOutcome::PidLimit, "processes")),
        Class::CpuLimit => Some((ProbeOutcome::CpuLimit, "cpu")),
        Class::MixedLimits => Some((ProbeOutcome::MixedLimits, mixed.as_str())),
        _ => None,
    };
    if let Some((outcome, limit)) = limit {
        return Err((
            outcome,
            Error::Rejected(format!(
                "corpus probe {} exceeds configured {limit} limit",
                class.name()
            )),
        ));
    }
    if residual_members {
        return Err((
            ProbeOutcome::Held,
            Error::Held("corpus probe retained tree members after launcher exit".into()),
        ));
    }
    match code {
        Some(0 | 1) => Ok(()),
        Some(2) => Err((
            ProbeOutcome::Held,
            Error::Rejected("corpus probe refused".into()),
        )),
        _ => Err((
            ProbeOutcome::Held,
            Error::Held("corpus probe incomplete".into()),
        )),
    }
}

pub(super) fn stage(
    store: &Store,
    bundle: &Path,
    input_bound: u64,
) -> Result<
    (
        crate::record::Text,
        crate::store::Dir,
        crate::sim::input::Staged,
    ),
    Error,
> {
    let mut source = crate::store::open_host(bundle).map_err(|error| {
        if error.faulted() {
            Error::Unreadable(error)
        } else {
            Error::Rejected(error.to_string())
        }
    })?;
    let identity = source.identity();
    let (id, dir) = super::super::probe::directory(store, super::PROBE_PREFIX)?;
    let mut staged =
        crate::sim::input::Stager::new((&mut source).take(input_bound.saturating_add(1)));
    if store.copy_once(&dir, &name("bundle"), &mut staged, 0o400)? != Creation::Created {
        return Err(Error::Held("corpus bundle already present".into()));
    }
    if let Some(error) = staged.read_error() {
        return Err(Error::Held(format!("corpus source read failed: {error}")));
    }
    if crate::store::open_host(bundle)?.identity() != identity {
        return Err(Error::Held("corpus source changed while staging".into()));
    }
    let staged = staged.finish().map_err(Error::Rejected)?;
    if staged.bytes > input_bound || staged.manifest.len() as u64 > BOUND {
        return Err(Error::Rejected(
            "corpus bundle or manifest exceeds its bound".into(),
        ));
    }
    Ok((id, dir, staged))
}

fn archive_error(error: crate::archive::Invalid) -> Error {
    if error.exit(false) == crate::exit::Sim::Rejected {
        Error::Rejected(error.to_string())
    } else {
        Error::Held(error.to_string())
    }
}
