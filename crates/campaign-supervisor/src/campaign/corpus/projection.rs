use super::{Catalog, Error, name, text, verify};
use crate::record::{CorpusProbe, ProbeFinished, ProbeOutcome};
use crate::store::ReadStore;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(in crate::campaign) fn project(
    store: &impl ReadStore,
    held: &mut Vec<Value>,
) -> Result<Value, Error> {
    let (version, assets, registered) = match Catalog::load(store) {
        Ok(catalog) => (
            json!(catalog.version),
            catalog
                .assets
                .iter()
                .map(|(id, row)| {
                    json!({
                        "asset": id, "record": row.asset, "semantic_key": row.asset.semantic_key(),
                        "state": if row.retired { "retired" } else { "registered" },
                        "eligible": row.eligible(), "version": row.version,
                        "bundle": format!("probes/{}/bundle", row.asset.probe.attempt.as_str()),
                        "manifest": format!("probes/{}/manifest", row.asset.probe.attempt.as_str()),
                    })
                })
                .collect::<Vec<_>>(),
            catalog
                .assets
                .into_values()
                .map(|row| (row.asset.probe.attempt.clone(), row.asset.probe))
                .collect(),
        ),
        Err(error) => {
            super::super::projection::held(held, "corpus", error)?;
            (Value::Null, Vec::new(), BTreeMap::new())
        }
    };
    let mut probes = Vec::new();
    if let Some(root) = super::super::projection::root(store, "probes", held)? {
        for entry in super::super::projection::entries(store, &root, "probes", held)? {
            if !super::is_probe(entry.as_str()) {
                continue;
            }
            let checked = (|| -> Result<Value, Error> {
                let dir = store
                    .open_dir(&root, &entry)?
                    .ok_or_else(|| Error::Held("corpus probe missing".into()))?;
                let probe = store.read_record::<CorpusProbe>(&dir, &name("corpus-probe"))?;
                let finish = store.read_record::<ProbeFinished>(&dir, &name("finished"))?;
                let id = text(entry.as_str())?;
                let charged = crate::custody::charged(store, &dir, &id)?.is_some();
                if let Some(probe) = &probe {
                    if probe.record().attempt != id {
                        return Err(Error::Held("corpus probe name differs".into()));
                    }
                    store.barrier(probe.read())?;
                }
                if let Some(finish) = &finish {
                    if finish.record().attempt != id {
                        return Err(Error::Held("corpus probe finish differs".into()));
                    }
                    store.barrier(finish.read())?;
                    if finish.record().outcome == ProbeOutcome::Complete {
                        let probe = probe
                            .as_ref()
                            .ok_or_else(|| Error::Held("corpus probe inputs missing".into()))?;
                        // Catalog::load verified the lifecycle and stored result of this probe
                        // directory for the identical probe record.
                        if registered.get(&id) != Some(probe.record()) {
                            super::super::probe::released(store, &dir, &probe.record().attempt)?;
                            verify::stored_result(store, &dir, probe.record())?;
                        }
                    }
                }
                let state = match finish.as_ref().map(|finish| finish.record().outcome) {
                    Some(ProbeOutcome::Complete) => "verified",
                    Some(ProbeOutcome::Held) => "held",
                    Some(ProbeOutcome::OutputLimit) => "output-limit",
                    Some(ProbeOutcome::Oom) => "oom",
                    Some(ProbeOutcome::PidLimit) => "pid-limit",
                    Some(ProbeOutcome::CpuLimit) => "cpu-limit",
                    Some(ProbeOutcome::MixedLimits) => "mixed-limits",
                    None => "unfinished",
                };
                Ok(json!({
                    "probe": id,
                    "record": probe.as_ref().map(|probe| probe.record()),
                    "charged": charged,
                    "state": state,
                }))
            })();
            match checked {
                Ok(row) => probes.push(row),
                Err(error) => super::super::projection::held(
                    held,
                    &format!("probes/{}", entry.as_str()),
                    error,
                )?,
            }
        }
    }
    Ok(json!({"version": version, "assets": assets, "probes": probes}))
}
