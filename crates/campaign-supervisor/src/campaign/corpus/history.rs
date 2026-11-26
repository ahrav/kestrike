use super::{Error, name, once, verify};
use crate::record::{CorpusAsset, CorpusProbe, CorpusRetirement, CorpusVersion, Digest, Record};
use crate::store::{Dir, ReadStore, Store};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct Registered {
    pub asset: CorpusAsset,
    pub retired: bool,
    pub version: Option<u64>,
}

impl Registered {
    pub(crate) fn eligible(&self) -> bool {
        !self.retired && self.version.is_some()
    }
}

pub(crate) struct Catalog {
    pub assets: BTreeMap<Digest, Registered>,
    pub version: u64,
    changes: BTreeSet<(Digest, bool)>,
}

pub(super) fn directory(store: &Store, parent: &Dir, entry: &str) -> Result<Dir, Error> {
    store.mkdir(parent, &name(entry))?;
    store
        .open_dir(parent, &name(entry))?
        .ok_or_else(|| Error::Held("corpus directory vanished".into()))
}

impl Catalog {
    pub(super) fn active(&self) -> u64 {
        self.assets.values().filter(|row| !row.retired).count() as u64
    }

    pub(crate) fn load(store: &impl ReadStore) -> Result<Self, Error> {
        let mut catalog = Self {
            assets: BTreeMap::new(),
            version: 0,
            changes: BTreeSet::new(),
        };
        let Some(corpus) = store.open_dir(store.root(), &name("corpus"))? else {
            return Ok(catalog);
        };
        for entry in store.list(&corpus, crate::scan_bound())? {
            if !matches!(entry.as_str(), "assets" | "versions") {
                return Err(Error::Held("undeclared corpus entry".into()));
            }
        }
        if let Some(assets) = store.open_dir(&corpus, &name("assets"))? {
            let mut keys = BTreeSet::new();
            for entry in store.list(&assets, crate::scan_bound())? {
                let id = Digest::parse(entry.as_str())
                    .ok_or_else(|| Error::Held("invalid corpus asset name".into()))?;
                let dir = store
                    .open_dir(&assets, &entry)?
                    .ok_or_else(|| Error::Held("corpus asset directory missing".into()))?;
                let entries = store.list(&dir, crate::scan_bound())?;
                if entries
                    .iter()
                    .any(|entry| !matches!(entry.as_str(), "asset" | "retired"))
                {
                    return Err(Error::Held("undeclared corpus asset entry".into()));
                }
                let Some(asset) = store.read_record::<CorpusAsset>(&dir, &name("asset"))? else {
                    if !entries.is_empty() {
                        return Err(Error::Held("unsealed corpus asset".into()));
                    }
                    continue;
                };
                if asset.record().id() != id || !keys.insert(asset.record().semantic_key()) {
                    return Err(Error::Held(
                        "corpus identity or semantic key differs".into(),
                    ));
                }
                let probe = probe_directory(store, &asset.record().probe)?;
                super::super::probe::released(store, &probe, &asset.record().probe.attempt)?;
                if verify::stored_result(store, &probe, &asset.record().probe)? != *asset.record() {
                    return Err(Error::Held(
                        "corpus asset differs from verified probe".into(),
                    ));
                }
                let retirement = store.read_record::<CorpusRetirement>(&dir, &name("retired"))?;
                if let Some(retirement) = &retirement {
                    if retirement.record().asset != id {
                        return Err(Error::Held("corpus retirement names another asset".into()));
                    }
                    store.barrier(retirement.read())?;
                }
                store.barrier(asset.read())?;
                catalog.assets.insert(
                    id,
                    Registered {
                        asset: asset.record().clone(),
                        retired: retirement.is_some(),
                        version: None,
                    },
                );
            }
        }
        if let Some(versions) = store.open_dir(&corpus, &name("versions"))? {
            let mut records = BTreeMap::new();
            for entry in store.list(&versions, crate::scan_bound())? {
                let version = store
                    .read_record::<CorpusVersion>(&versions, &entry)?
                    .ok_or_else(|| Error::Held("corpus version missing".into()))?;
                if version.record().number.to_string() != entry.as_str()
                    || version.record().number == 0
                {
                    return Err(Error::Held("corpus version name differs".into()));
                }
                store.barrier(version.read())?;
                records.insert(version.record().number, version.record().clone());
            }
            for (number, version) in records {
                let row = catalog
                    .assets
                    .get_mut(&version.asset)
                    .ok_or_else(|| Error::Held("corpus version asset missing".into()))?;
                if number != catalog.version + 1
                    || !catalog.changes.insert((version.asset, version.retired))
                    || (version.retired && (!row.retired || row.version.is_none()))
                {
                    return Err(Error::Held("corpus version history differs".into()));
                }
                if !version.retired {
                    row.version = Some(number);
                }
                catalog.version = number;
            }
        }
        Ok(catalog)
    }
}

/// The name prefix of a corpus registration probe in `probes/`.
pub(in crate::campaign) const PROBE_PREFIX: &str = "corpus-probe";

/// Whether the `probes/` entry `entry` names a corpus registration probe:
/// [`PROBE_PREFIX`] followed by a dash.
pub(in crate::campaign) fn is_probe(entry: &str) -> bool {
    entry
        .strip_prefix(PROBE_PREFIX)
        .is_some_and(|rest| rest.starts_with('-'))
}

pub(super) fn probe_directory(store: &impl ReadStore, probe: &CorpusProbe) -> Result<Dir, Error> {
    let probes = store
        .open_dir(store.root(), &name("probes"))?
        .ok_or_else(|| Error::Held("corpus probes missing".into()))?;
    let dir = store
        .open_dir(
            &probes,
            &crate::store::Name::new(probe.attempt.as_str())
                .ok_or_else(|| Error::Held("invalid corpus probe name".into()))?,
        )?
        .ok_or_else(|| Error::Held("corpus probe missing".into()))?;
    let found = store
        .read_record::<CorpusProbe>(&dir, &name("corpus-probe"))?
        .ok_or_else(|| Error::Held("corpus probe record missing".into()))?;
    if found.record() != probe {
        return Err(Error::Held("corpus probe inputs differ".into()));
    }
    store.barrier(found.read())?;
    Ok(dir)
}

pub(in crate::campaign) fn reconcile(store: &Store) -> Result<Catalog, Error> {
    let mut catalog = Catalog::load(store)?;
    if catalog.assets.is_empty() {
        return Ok(catalog);
    }
    let corpus = directory(store, store.root(), "corpus")?;
    let versions = directory(store, &corpus, "versions")?;
    for (&id, row) in &mut catalog.assets {
        for retired in [false, true] {
            if (retired && !row.retired) || catalog.changes.contains(&(id, retired)) {
                continue;
            }
            if catalog.version as usize >= crate::scan_bound() {
                return Err(Error::Held(Error::authority_full("corpus version")));
            }
            catalog.version += 1;
            once(
                store,
                &versions,
                &catalog.version.to_string(),
                &CorpusVersion {
                    asset: id,
                    number: catalog.version,
                    retired,
                },
            )?;
            catalog.changes.insert((id, retired));
            if !retired {
                row.version = Some(catalog.version);
            }
        }
    }
    Ok(catalog)
}

pub(in crate::campaign) fn remove(store: &Store, id: Digest) -> Result<u64, Error> {
    let catalog = reconcile(store)?;
    let row = catalog
        .assets
        .get(&id)
        .ok_or_else(|| Error::Rejected("unknown corpus asset".into()))?;
    if row.retired {
        return Ok(catalog.version);
    }
    if catalog.version as usize >= crate::scan_bound() {
        return Err(Error::Held(Error::authority_full("corpus version")));
    }
    let corpus = directory(store, store.root(), "corpus")?;
    let assets = directory(store, &corpus, "assets")?;
    let dir = store
        .open_dir(&assets, &name(&id.to_string()))?
        .ok_or_else(|| Error::Held("corpus asset missing".into()))?;
    once(store, &dir, "retired", &CorpusRetirement { asset: id })?;
    Ok(reconcile(store)?.version)
}

pub(super) fn retirement_reserve(id: Digest) -> u64 {
    CorpusRetirement { asset: id }.encoded_len() as u64
        + CorpusVersion {
            asset: id,
            number: u64::MAX,
            retired: true,
        }
        .encoded_len() as u64
}

pub(super) fn retained_bytes(store: &Store, catalog: &Catalog) -> Result<u64, Error> {
    let mut bytes = 0u64;
    if let Some(corpus) = store.open_dir(store.root(), &name("corpus"))? {
        bytes = corpus.usage(crate::scan_bound())?.bytes;
    }
    for row in catalog.assets.values() {
        bytes = bytes.saturating_add(
            probe_directory(store, &row.asset.probe)?
                .usage(crate::scan_bound())?
                .bytes,
        );
    }
    for (&id, row) in &catalog.assets {
        if !row.retired {
            bytes = bytes.saturating_add(retirement_reserve(id));
        }
    }
    Ok(bytes)
}

pub(in crate::campaign) fn target_input(
    store: &crate::store::Store,
    id: crate::record::Digest,
) -> Result<(crate::record::CorpusAsset, String, crate::store::Dir, u64), Error> {
    let catalog = Catalog::load(store)?;
    if catalog.assets.get(&id).is_none_or(|row| row.retired) {
        return Err(Error::Rejected(
            "target requires an active registered asset".into(),
        ));
    }
    let catalog = reconcile(store)?;
    let row = catalog
        .assets
        .get(&id)
        .filter(|row| row.eligible())
        .ok_or_else(|| Error::Rejected("target requires an active registered asset".into()))?;
    let directory = probe_directory(store, &row.asset.probe)?;
    let manifest = verify::inputs(store, &directory, &row.asset.probe)?;
    Ok((row.asset.clone(), manifest, directory, catalog.version))
}
