use super::{Error, name, text};
use crate::protocol::{Branch, Class, Listing};
use crate::record::{Artifact, BOUND, CorpusAsset, CorpusProbe, Digest};
use crate::sim::input::{RECORD, Tag};
use crate::store::{Dir, ReadStore};
use sha2::{Digest as _, Sha256};
use std::io::Read;

pub(super) fn inputs(
    store: &impl ReadStore,
    dir: &Dir,
    probe: &CorpusProbe,
) -> Result<String, Error> {
    if store.evidence_digest(dir, &name("bundle"), probe.bytes)? != Some(probe.bundle) {
        return Err(Error::Held("corpus bundle digest differs".into()));
    }
    let manifest = store
        .read(dir, &name("manifest"), BOUND)?
        .ok_or_else(|| Error::Held("corpus manifest missing".into()))?;
    if Digest::of(manifest.bytes()) != probe.manifest {
        return Err(Error::Held("corpus manifest digest differs".into()));
    }
    store.barrier(&manifest)?;
    String::from_utf8(manifest.bytes().to_vec()).map_err(|e| Error::Held(e.to_string()))
}

pub(super) fn stored_result(
    store: &impl ReadStore,
    dir: &Dir,
    probe: &CorpusProbe,
) -> Result<CorpusAsset, Error> {
    result(store, dir, probe, None).map_err(|error| match error {
        Error::Rejected(reason) => Error::Held(reason),
        error => error,
    })
}

pub(super) fn result(
    store: &impl ReadStore,
    dir: &Dir,
    probe: &CorpusProbe,
    code: Option<i32>,
) -> Result<CorpusAsset, Error> {
    let manifest = inputs(store, dir, probe)?;
    let artifacts = store
        .open_dir(dir, &name("artifacts"))?
        .ok_or_else(|| Error::Held("corpus probe artifacts missing".into()))?;
    let evidence = store
        .open_dir(&artifacts, &name(probe.attempt.as_str()))?
        .ok_or_else(|| Error::Held("corpus probe evidence missing".into()))?;
    let artifact = store
        .read_record::<Artifact>(&evidence, &name("artifact"))?
        .ok_or_else(|| Error::Held("corpus probe artifact missing".into()))?;
    let artifact = {
        store.barrier(artifact.read())?;
        artifact.record().clone()
    };
    let class = artifact.class.as_str();
    if artifact.archive != Some(probe.archive)
        || artifact.bundle != Some(probe.bundle)
        || artifact.manifest != Some(Digest::of(&crate::sim::input::worker_manifest(&manifest)))
        || artifact.run_id != probe.attempt
        || artifact.command.as_str() != "branch"
        || !matches!(class, "counts" | "complete")
        || code.is_some_and(|code| code != if class == "counts" { 0 } else { 1 })
    {
        return Err(Error::Held("corpus probe artifact binding differs".into()));
    }
    let output = phase(store, &evidence, &artifact, "branch")?;
    let listing = Listing::parse(&phase(store, &evidence, &artifact, "capabilities")?)
        .map_err(|e| Error::Held(e.to_string()))?;
    let values =
        crate::sim::input::Values::parse(&manifest, "corpus bundle").map_err(Error::Rejected)?;
    let profile = values
        .profile()
        .ok_or_else(|| Error::Rejected("corpus profile missing".into()))?;
    if !listing
        .milestones
        .iter()
        .any(|m| m == probe.milestone.as_str())
        || probe.milestone.as_str().starts_with("recovery-")
        || profile.starts_with("recovery-")
        || listing
            .profile(profile)
            .is_none_or(|p| p.class == Class::Recovery)
    {
        return Err(Error::Rejected(
            "corpus requires a listed non-recovery milestone and profile".into(),
        ));
    }
    let branch = Branch::parse(&output)
        .map_err(|e| Error::Held(e.to_string()))?
        .ok_or_else(|| Error::Rejected("corpus prefix replay diverged".into()))?;
    if !branch.reproduced
        || branch.milestone.name != probe.milestone.as_str()
        || branch.children.len() != 1
        || branch.children[0].suffix != 0
        || branch.children[0].sibling != 0
        || branch.milestone.semantic == 0
    {
        return Err(Error::Rejected(
            "corpus probe prefix or child set differs".into(),
        ));
    }
    if branch.witness.milestone != "pending-put"
        || branch.witness.upload.is_none_or(|upload| {
            upload.attempt == 0 || upload.grant == 0 || upload.held == 0 || upload.outcome != 0
        })
    {
        return Err(Error::Rejected(
            "corpus witness facts do not satisfy the milestone".into(),
        ));
    }
    let (prefix, state) = prefixes(store, dir, probe.bytes, branch.milestone.semantic)?;
    if prefix != branch.milestone.prefix {
        return Err(Error::Rejected(
            "corpus prefix differs from the frozen bundle".into(),
        ));
    }
    Ok(CorpusAsset {
        boundary: branch.milestone.boundary,
        decisions: branch.milestone.decisions,
        prefix,
        probe: probe.clone(),
        profile: text(profile)?,
        root: root(&manifest)?,
        semantic: branch.milestone.semantic,
        state,
    })
}

fn phase(
    store: &impl ReadStore,
    dir: &Dir,
    artifact: &Artifact,
    phase: &str,
) -> Result<String, Error> {
    let stdout = store
        .read(dir, &name(&format!("{phase}.stdout")), BOUND)?
        .ok_or_else(|| Error::Held("corpus probe stdout missing".into()))?;
    let worker = artifact
        .workers
        .get(&text(phase)?)
        .ok_or_else(|| Error::Held("corpus probe phase missing".into()))?;
    if worker.stdout != Digest::of(stdout.bytes())
        || worker.ended.as_str() != "exited"
        || worker.signal.is_some()
        || !worker.exit.is_some_and(|code| {
            if phase == "capabilities" {
                code == 0
            } else {
                code <= 1
            }
        })
    {
        return Err(Error::Held("corpus probe phase binding differs".into()));
    }
    store.barrier(&stdout)?;
    String::from_utf8(stdout.bytes().to_vec()).map_err(|e| Error::Held(e.to_string()))
}

fn root(manifest: &str) -> Result<u64, Error> {
    let roots: Vec<_> = manifest
        .lines()
        .filter_map(|line| line.strip_prefix("root = "))
        .collect();
    if let [value] = roots.as_slice()
        && let Ok(root) = value.parse::<u64>()
        && root > 0
        && root.to_string() == *value
    {
        return Ok(root);
    }
    Err(Error::Rejected(
        "corpus root requires one positive canonical integer".into(),
    ))
}

pub(super) fn prefixes(
    store: &impl ReadStore,
    dir: &Dir,
    bytes: u64,
    semantic: u64,
) -> Result<(Digest, Digest), Error> {
    let mut bundle = std::io::BufReader::new(
        store
            .open_file(dir, &name("bundle"))?
            .ok_or_else(|| Error::Held("corpus bundle missing".into()))?
            .take(bytes),
    );
    let mut full = Sha256::new();
    let mut state = Sha256::new();
    let mut taken = 0;
    let mut record = [0; RECORD];
    while taken < semantic {
        bundle.read_exact(&mut record).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => Error::Rejected(e.to_string()),
            _ => Error::Unreadable(e.into()),
        })?;
        match Tag::of(record[0]) {
            Tag::Unknown => {
                return Err(Error::Rejected(format!(
                    "corpus bundle has unknown record tag {}",
                    record[0]
                )));
            }
            Tag::Skipped => {}
            Tag::Semantic => {
                full.update(record);
                if (4..=7).contains(&record[0]) {
                    state.update(record);
                }
                taken += 1;
            }
        }
    }
    Ok((Digest::finish(full), Digest::finish(state)))
}
