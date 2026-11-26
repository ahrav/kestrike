//! A test builder of campaign state for the census. It admits jobs through
//! the store and writes placeholder attempt, probe and root-entry
//! directories through it, without a worker or a cgroup. The placeholders
//! hold empty files and no lifecycle records, so the census counts them and
//! dispatch, attempt and findings readers refuse them. Whole-probe builders
//! write released lifecycle records, launcher streams and bound capability
//! evidence that reconciliation, report and collect accept.

use std::collections::BTreeMap;

use super::{Request, name};
use crate::attempt::tests::{admit_request, text};
use crate::record::{Admission, Configuration};
use crate::store::{Dir, Store};

/// A configuration with the given `attempt_output` and `attempt_inodes`.
pub(crate) fn config(attempt_output: u64, attempt_inodes: u64) -> Configuration {
    let values: BTreeMap<_, _> = [
        ("slots", 2),
        ("reserve_slots", 1),
        ("cores", 4),
        ("memory", 1 << 30),
        ("cpu", 10),
        ("tree_memory", 128 << 20),
        ("attempt_output", attempt_output),
        ("attempt_inodes", attempt_inodes),
        ("wall", 60),
        ("processes", 64),
        ("artifact_bytes", 1 << 40),
        ("artifact_inodes", 1 << 30),
        ("backlog", 10),
        ("retained_builds", 1),
    ]
    .into_iter()
    .map(|(key, value)| (text(key), value))
    .collect();
    Configuration::new(values).expect("the fixture configuration is valid")
}

/// Admits the campaign job of run `run` and returns its record.
pub(crate) fn job(store: &Store, run: u64) -> Admission {
    admit_request(
        store,
        &Request {
            profile: text("upload"),
            campaign: text("fixture"),
            run,
            attempts: 3,
            counts: BTreeMap::new(),
        },
    )
    .expect("the fixture job is admitted")
    .record
}

/// The admission record of a branch target of `ordinary` with `siblings`
/// siblings of one suffix each, so the job runs under `siblings + 1` fork
/// shares. Its target names a 48-byte zero bundle.
pub(crate) fn target_admission(ordinary: &Admission, siblings: u64) -> Admission {
    use crate::record::{Digest, ForkForm, Job, Target};
    let mut experiment = ordinary.job().experiment().clone();
    experiment.format = 2;
    experiment.target = Some(Target {
        asset: Digest::of(b"asset"),
        boundary: 13,
        build: Digest::parse(ordinary.job().experiment().pins.build.as_str())
            .expect("the fixture build is a digest"),
        bundle: Digest::of(&[0; 48]),
        bytes: 48,
        decisions: 1,
        form: ForkForm::Branch {
            siblings,
            suffixes: 1,
        },
        manifest: ordinary.job().manifest_sha256(),
        milestone: text("pending-put"),
        prefix: Digest::of(b"prefix"),
        root: ordinary.job().seed(),
        semantic: 1,
    });
    let job = Job::targeted(experiment).expect("the fixture target is valid");
    Admission::targeted(ordinary.archive().clone(), job, 1).expect("the fixture admission is valid")
}

/// Replaces an ordinary admission's record and manifest with a targeted
/// admission, retaining the original manifest bytes and freezing `bundle`.
pub(crate) fn retarget(store: &Store, original: &Admission, target: &Admission, bundle: &[u8]) {
    let (old, new) = (original.job().id(), target.job().id());
    let shard = |id: String| {
        crate::layout::make_shard(store, crate::layout::JOBS, &id)
            .expect("the fixture shard is created")
    };
    let (jobs, created) = (shard(old.to_string()), shard(new.to_string()));
    let manifest = store
        .read(
            &jobs,
            &name(&format!("{old}.manifest")),
            crate::record::BOUND,
        )
        .expect("the fixture manifest reads")
        .expect("the fixture manifest reads");
    store
        .create_record(&created, &name(&format!("{new}.json")), target)
        .unwrap();
    store
        .create_once(
            &created,
            &name(&format!("{new}.manifest")),
            manifest.bytes(),
        )
        .unwrap();
    store
        .create_once(&created, &name(&format!("{new}.bundle")), bundle)
        .unwrap();
    store.delete(&jobs, &name(&format!("{old}.json"))).unwrap();
    store
        .delete(&jobs, &name(&format!("{old}.manifest")))
        .unwrap();
}

/// Writes [`target_admission`]'s record and returns it. The record has no
/// frozen bundle or manifest beside it.
pub(crate) fn targeted(store: &Store, ordinary: &Admission, siblings: u64) -> Admission {
    let admission = target_admission(ordinary, siblings);
    let jobs = crate::layout::make_shard(
        store,
        crate::layout::JOBS,
        &admission.job().id().to_string(),
    )
    .expect("the fixture shard is created");
    super::once(
        store,
        &jobs,
        &format!("{}.json", admission.job().id()),
        &admission,
    )
    .expect("the fixture admission is written");
    admission
}

/// Opens `component` beneath `parent`, creating it first.
fn directory(store: &Store, parent: &Dir, component: &str) -> Dir {
    store
        .mkdir(parent, &name(component))
        .expect("the fixture directory is created");
    store
        .open_dir(parent, &name(component))
        .expect("the fixture directory opens")
        .expect("the fixture directory is present")
}

/// Writes `files` empty files named `file-<k>` into `directory`.
fn fill(store: &Store, directory: &Dir, files: usize) {
    for index in 0..files {
        store
            .create_once(directory, &name(&format!("file-{index}")), b"")
            .expect("the fixture file is written");
    }
}

/// Writes the placeholder directory of attempt `number` of `job`, holding
/// `files` empty files.
pub(crate) fn attempt(store: &Store, job: &Admission, number: u64, files: usize) {
    let id = job.job().id().to_string();
    let attempts =
        crate::layout::make_shard(store, crate::layout::ATTEMPTS, &id).expect("the shard opens");
    let history = directory(store, &attempts, &id);
    fill(
        store,
        &directory(store, &history, &format!("{number:04}")),
        files,
    );
}

/// Writes the placeholder probe directory `probe`, holding `files` empty
/// files.
pub(crate) fn probe(store: &Store, probe: &str, files: usize) {
    let probes = directory(store, store.root(), "probes");
    fill(store, &directory(store, &probes, probe), files);
}

/// Writes `bytes` bytes as `jobs/<stem>.bundle`, with no admission record
/// for `stem`.
pub(crate) fn bundle(store: &Store, stem: &str, bytes: usize) {
    let jobs = crate::layout::make_shard(store, crate::layout::JOBS, stem)
        .expect("the fixture shard is created");
    store
        .create_once(&jobs, &name(&format!("{stem}.bundle")), &vec![0; bytes])
        .expect("the fixture bundle is written");
}

/// Writes `entries` empty placeholder directories under the root `root`.
pub(crate) fn entries(store: &Store, root: &str, entries: usize) {
    let parent = directory(store, store.root(), root);
    for index in 0..entries {
        directory(store, &parent, &format!("entry-{index}"));
    }
}

/// The complete capability artifact for the fixture listing of `build`.
pub(crate) fn capability_artifact(build: crate::record::Digest) -> crate::record::Artifact {
    use crate::record::{Artifact, Digest, Worker};
    Artifact {
        archive: Some(build),
        archive_path: None,
        bundle: None,
        class: text("counts"),
        command: text("capabilities"),
        comparison: None,
        manifest: None,
        output: None,
        reason: text(""),
        run_id: text("probe"),
        session: None,
        session_original: None,
        summary: None,
        workers: BTreeMap::from([(
            text("capabilities"),
            Worker {
                ended: text("exited"),
                exit: Some(0),
                signal: None,
                stderr: Digest::of(b""),
                stdout: Digest::of(include_bytes!("../../testdata/admission-listing.txt")),
            },
        )]),
    }
}

/// Writes the released admission probe `probe` of the default build, as
/// [`finished_probe`] writes a completed one.
pub(crate) fn released_probe(store: &Store, probe: &str, cgroup: &str) -> Dir {
    finished_probe(
        store,
        probe,
        cgroup,
        crate::record::Digest::of(b"archive"),
        crate::record::ProbeOutcome::Complete,
    )
}

/// Writes the released admission probe `probe`: its lifecycle records with
/// `cgroup` as the recorded cgroup and `outcome` as the finished outcome,
/// its launcher streams, and the nested evidence store `artifacts/probe`
/// with the capabilities artifact of the archive build `build` and its
/// streams, as a finished and released probe leaves them.
pub(crate) fn finished_probe(
    store: &Store,
    probe: &str,
    cgroup: &str,
    build: crate::record::Digest,
    outcome: crate::record::ProbeOutcome,
) -> Dir {
    use crate::record::{Intent, ProbeFinished, Started};
    let probes = directory(store, store.root(), "probes");
    let probe_dir = directory(store, &probes, probe);
    let boot = text(&crate::store::cgroup::boot().expect("the boot id reads"));
    let intent = Intent {
        attempt: text(probe),
        boot: boot.clone(),
        cgroup: text(cgroup),
    };
    store
        .create_record(&probe_dir, &name("intent"), &intent)
        .expect("the intent is written");
    store
        .create_record(
            &probe_dir,
            &name("started"),
            &Started {
                attempt: text(probe),
                baseline: Default::default(),
                boot,
                cgroup: text(cgroup),
                cgroup_inode: 1,
                launcher_pid: 1,
            },
        )
        .expect("the started record is written");
    for stream in [
        crate::custody::LAUNCHER_STDOUT,
        crate::custody::LAUNCHER_STDERR,
    ] {
        store
            .create_once(&probe_dir, &name(stream), b"")
            .expect("the launcher stream is written");
    }
    let artifacts = directory(store, &probe_dir, "artifacts");
    directory(store, &artifacts, "probe");
    let listing = include_bytes!("../../testdata/admission-listing.txt");
    let evidence = Store::open(&store.path().join(format!("probes/{probe}/artifacts/probe")))
        .expect("the evidence store opens");
    evidence
        .create_record(
            evidence.root(),
            &name("artifact"),
            &capability_artifact(build),
        )
        .expect("the artifact is written");
    for (stream, bytes) in [
        ("capabilities.stdout", &listing[..]),
        ("capabilities.stderr", b""),
    ] {
        evidence
            .create_once(evidence.root(), &name(stream), bytes)
            .expect("the evidence stream is written");
    }
    drop(evidence);
    store
        .create_record(
            &probe_dir,
            &name("finished"),
            &ProbeFinished {
                attempt: text(probe),
                outcome,
            },
        )
        .expect("the finished record is written");
    probe_dir
}

/// The path of the job-record file `file` relative to the state directory,
/// in the shard of the job id that starts `file`.
pub(crate) fn job_file(file: impl AsRef<str>) -> std::path::PathBuf {
    let file = file.as_ref();
    crate::layout::job_file(file, file)
}

/// The path of job `id`'s attempt directory relative to the state
/// directory.
pub(crate) fn attempts_dir(id: impl AsRef<str>) -> std::path::PathBuf {
    let id = id.as_ref();
    std::path::PathBuf::from(crate::layout::ATTEMPTS)
        .join(crate::layout::shard(id).as_str())
        .join(id)
}

pub(crate) fn job_file_lengths_by_shard(state: &std::path::Path) -> Vec<Vec<u64>> {
    let mut shards = BTreeMap::<std::path::PathBuf, Vec<u64>>::new();
    for (path, contents) in crate::store::fixture::snapshot(&state.join(crate::layout::JOBS)) {
        match contents {
            Some(bytes) => shards
                .entry(path.parent().unwrap().to_path_buf())
                .or_default()
                .push(bytes.len() as u64),
            None => {
                shards.entry(path).or_default();
            }
        }
    }
    shards.into_values().collect()
}

pub(crate) fn job_file_lengths(state: &std::path::Path) -> Vec<u64> {
    job_file_lengths_by_shard(state)
        .into_iter()
        .flatten()
        .collect()
}

pub(crate) fn result_path(
    state: &std::path::Path,
    id: impl std::fmt::Display,
) -> std::path::PathBuf {
    state.join(job_file(format!("{id}.result.json")))
}

/// Opens job directories through the sharded layout by job id.
pub(crate) trait Sharded: crate::store::ReadStore + Sized {
    /// The shard of `jobs/` holding job `id`'s records; a store creates it.
    fn shard_jobs(&self, id: impl ToString) -> Result<Option<Dir>, crate::store::Unreadable> {
        crate::layout::jobs(self, &id.to_string())
    }
}
impl Sharded for Store {
    fn shard_jobs(&self, id: impl ToString) -> Result<Option<Dir>, crate::store::Unreadable> {
        Ok(Some(
            crate::layout::make_shard(self, crate::layout::JOBS, &id.to_string())
                .expect("the fixture shard is created"),
        ))
    }
}
impl Sharded for crate::store::View {}

/// Counts `store` under a scan bound of `bound`, restoring the step seam
/// after the count so later operations use their own bound.
pub(crate) fn counted_at(store: &Store, bound: usize) -> Result<(), super::Error> {
    crate::store::fixture::bounded(bound, || super::census::Census::count(store).map(drop)).0
}
