use super::{Error, name, text};
use crate::record::{Hardware, HardwareClass, HardwareDisposition, HardwarePhase};
use crate::store::{Creation, Dir, ReadStore, Store, View};
use serde_json::{Value, json};

fn root(store: &impl ReadStore) -> Result<Option<Dir>, Error> {
    Ok(store.open_dir(store.root(), &name("runs"))?)
}

fn entries(store: &impl ReadStore, root: &Dir) -> Result<Vec<(u64, crate::store::Name)>, Error> {
    let mut entries = Vec::new();
    for entry in store.list(root, crate::scan_bound())? {
        let number = entry
            .as_str()
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0 && format!("{n:04}") == entry.as_str())
            .ok_or_else(|| {
                Error::Held(format!("invalid hardware run directory {}", entry.as_str()))
            })?;
        entries.push((number, entry));
    }
    entries.sort_by_key(|entry| entry.0);
    Ok(entries)
}

fn each_run(
    store: &impl ReadStore,
    mut visit: impl FnMut(u64, &Dir) -> Result<(), Error>,
) -> Result<(), Error> {
    let Some(root) = root(store)? else {
        return Ok(());
    };
    for (number, entry) in entries(store, &root)? {
        let dir = store
            .open_dir(&root, &entry)?
            .ok_or_else(|| Error::Held("hardware directory vanished".into()))?;
        visit(number, &dir)?;
    }
    Ok(())
}

fn record(store: &impl ReadStore, dir: &Dir, number: u64) -> Result<Option<Hardware>, Error> {
    let mut selected: Option<Hardware> = None;
    for (file, phase) in [
        ("intent", HardwarePhase::Intent),
        ("started", HardwarePhase::Started),
        ("finished", HardwarePhase::Finished),
    ] {
        if let Some(found) = store.read_record::<Hardware>(dir, &name(file))? {
            store.barrier(found.read())?;
            let record = found.record();
            if record.number != number
                || record.phase != phase
                || (record.class.is_some() != (phase == HardwarePhase::Finished))
                || (record.exit.is_some() && record.signal.is_some())
            {
                return Err(Error::Held(
                    "hardware phase identity or verdict mismatch".into(),
                ));
            }
            let previous_phase = selected.as_ref().map(|record| record.phase);
            let valid_order = match phase {
                HardwarePhase::Intent => previous_phase.is_none(),
                HardwarePhase::Started => previous_phase == Some(HardwarePhase::Intent),
                HardwarePhase::Finished => match record.class {
                    Some(HardwareClass::Gated) => previous_phase.is_none(),
                    Some(HardwareClass::Unrun) => previous_phase == Some(HardwarePhase::Intent),
                    _ => previous_phase == Some(HardwarePhase::Started),
                },
            };
            if !valid_order {
                return Err(Error::Held(
                    "hardware lifecycle lacks a prerequisite phase".into(),
                ));
            }
            if let Some(previous) = &selected
                && (previous.argv != record.argv
                    || previous.kind != record.kind
                    || previous.profile != record.profile
                    || previous.platform != record.platform
                    || previous.directory != record.directory
                    || previous.custody_directory != record.custody_directory)
            {
                return Err(Error::Held(
                    "hardware phases name different admissions".into(),
                ));
            }
            selected = Some(record.clone());
        }
    }
    Ok(selected)
}

fn held(found: Result<Option<Hardware>, Error>) -> Result<Option<String>, Error> {
    match found {
        Ok(Some(record)) if record.phase == HardwarePhase::Started => {
            Ok(Some("controller exit and stop delivery are unknown".into()))
        }
        Ok(Some(record)) if record.class == Some(HardwareClass::Held) => {
            Ok(Some(record.reason.as_str().to_owned()))
        }
        Ok(_) => Ok(None),
        Err(error) if error.host_fault() => Err(error),
        Err(error) => Ok(Some(error.to_string())),
    }
}

fn disposed(store: &impl ReadStore, dir: &Dir, number: u64) -> Result<bool, Error> {
    let Some(found) = store.read_record::<HardwareDisposition>(dir, &name("disposition"))? else {
        return Ok(false);
    };
    store.barrier(found.read())?;
    if found.record().run() != number {
        return Err(Error::Held("disposition names another hardware run".into()));
    }
    Ok(true)
}

fn finish_lost(store: &Store, dir: &Dir, record: &mut Hardware) -> Result<(), Error> {
    if record.phase == HardwarePhase::Finished {
        return Ok(());
    }
    let (class, reason) = if record.phase == HardwarePhase::Started {
        (
            HardwareClass::Held,
            "supervisor lost after started; controller exit and stop delivery are unknown; controller may retain custody",
        )
    } else {
        (HardwareClass::Unrun, "supervisor lost before started")
    };
    record.phase = HardwarePhase::Finished;
    record.class = Some(class);
    record.reason = text(reason)?;
    write(store, dir, "finished", record)
}

pub(super) fn reconcile(store: &Store) -> Result<(), Error> {
    each_run(store, |number, dir| {
        if let Ok(Some(mut record)) = record(store, dir, number) {
            finish_lost(store, dir, &mut record)?;
        }
        Ok(())
    })
}

pub(super) fn admit(store: &Store) -> Result<(), Error> {
    let mut refusal = None;
    each_run(store, |number, dir| {
        let mut found = record(store, dir, number);
        if let Ok(Some(record)) = &mut found {
            finish_lost(store, dir, record)?;
        }
        if refusal.is_none()
            && !disposed(store, dir, number)?
            && let Some(reason) = held(found)?
        {
            refusal = Some(Error::Held(format!(
                "hardware run {number:04} requires evidence-backed disposition: {reason}"
            )));
        }
        Ok(())
    })?;
    refusal.map_or(Ok(()), Err)
}

pub(super) fn campaign_headroom(parent: &View) -> Result<(), Error> {
    let Some(config) =
        parent.read_record::<crate::record::Configuration>(parent.root(), &name("config.json"))?
    else {
        return Ok(());
    };
    parent.barrier(config.read())?;
    let config = config.record();
    let (free_bytes, free_inodes, fragment_bytes) = parent.root().free_space()?;
    let mut usage = parent.root().usage(crate::scan_bound())?;
    usage.free_bytes = free_bytes;
    usage.free_inodes = free_inodes;
    usage.fragment_bytes = fragment_bytes;
    let paused = crate::campaign::dispatch::storage_pauses(
        config,
        usage,
        config.value("slots").saturating_sub(1),
        config.value("reserve_slots"),
    );
    if paused.is_empty() {
        return Ok(());
    }
    Err(Error::Rejected(format!(
        "campaign storage capacity: {}",
        paused.into_iter().collect::<Vec<_>>().join(", ")
    )))
}

pub(super) fn allocate(store: &Store) -> Result<(u64, Dir, std::path::PathBuf), Error> {
    store.mkdir(store.root(), &name("runs"))?;
    let root = root(store)?.ok_or_else(|| Error::Held("hardware root vanished".into()))?;
    let existing = entries(store, &root)?;
    if existing.len() >= crate::scan_bound() {
        return Err(Error::Held(
            "hardware run history reached the scan bound".into(),
        ));
    }
    let number = existing
        .last()
        .map(|entry| entry.0)
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| Error::Held("hardware run numbers exhausted".into()))?;
    let entry = name(&format!("{number:04}"));
    if store.mkdir(&root, &entry)? != Creation::Created {
        return Err(Error::Held("hardware run directory already present".into()));
    }
    let dir = store
        .open_dir(&root, &entry)?
        .ok_or_else(|| Error::Held("hardware run directory vanished".into()))?;
    let path = store.path().join("runs").join(entry.as_str());
    Ok((number, dir, path))
}

pub(super) fn write(store: &Store, dir: &Dir, file: &str, record: &Hardware) -> Result<(), Error> {
    if store.create_record(dir, &name(file), record)? != Creation::Created {
        return Err(Error::Held("hardware phase already present".into()));
    }
    Ok(())
}

pub(super) fn dispose(store: &Store, disposition: HardwareDisposition) -> Result<Creation, Error> {
    let root = root(store)?.ok_or_else(|| Error::Rejected("hardware run absent".into()))?;
    let dir = store
        .open_dir(&root, &name(&format!("{:04}", disposition.run())))?
        .ok_or_else(|| Error::Rejected("hardware run absent".into()))?;
    if held(record(store, &dir, disposition.run()))?.is_none() {
        return Err(Error::Rejected("hardware run is not held".into()));
    }
    let creation = store.create_record(&dir, &name("disposition"), &disposition)?;
    if !disposed(store, &dir, disposition.run())? {
        return Err(Error::Held("disposition vanished".into()));
    }
    Ok(creation)
}

pub(crate) fn rows(
    parent: &View,
    held_rows: &mut Vec<Value>,
) -> Result<(Option<View>, Vec<Value>), Error> {
    if parent.open_dir(parent.root(), &name("hardware"))?.is_none() {
        return Ok((None, Vec::new()));
    }
    let store = View::snapshot(&parent.path().join("hardware"))?;
    store.require_state_marker()?;
    let mut rows = Vec::new();
    if let Some(root) = root(&store)? {
        let mut entries = store.raw_list(&root, crate::scan_bound())?;
        entries.sort_unstable();
        for raw in entries {
            let label = String::from_utf8_lossy(&raw);
            let Some(entry) = std::str::from_utf8(&raw)
                .ok()
                .and_then(crate::store::Name::new)
            else {
                let error = Error::Store(crate::store::Error::Foreign(label.to_string()));
                held_rows.push(json!({"path": format!("hardware/runs/{label}"), "reason": error.to_string(), "held_code": error.held_code()}));
                continue;
            };
            let path = format!("hardware/runs/{}", entry.as_str());
            let number = entry
                .as_str()
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0 && format!("{n:04}") == entry.as_str());
            let result = (|| {
                let number = number.ok_or_else(|| {
                    Error::Held(format!("invalid hardware run directory {}", entry.as_str()))
                })?;
                let dir = store
                    .open_dir(&root, &entry)?
                    .ok_or_else(|| Error::Held("hardware directory vanished".into()))?;
                let mut row = match record(&store, &dir, number) {
                    Ok(Some(record)) => {
                        let (class, reason) = match record.phase {
                            HardwarePhase::Started => (Some(HardwareClass::Held), "supervisor lost after started; controller exit and stop delivery are unknown".to_owned()),
                            HardwarePhase::Intent => (Some(HardwareClass::Unrun), "supervisor lost before started".to_owned()),
                            HardwarePhase::Finished => (record.class, record.reason.as_str().to_owned()),
                        };
                        json!({"run": format!("{number:04}"), "argv": record.argv, "profile": record.profile, "platform": record.platform, "kind": record.kind, "class": class, "phase": record.phase, "reason": reason, "exit": record.exit, "signal": record.signal, "directory": record.directory})
                    }
                    Ok(None) => {
                        json!({"run": format!("{number:04}"), "class": "unrun", "reason": "admission has no phase record"})
                    }
                    Err(error) if error.host_fault() => return Err(error),
                    Err(error) => {
                        held_rows.push(json!({"path": path, "reason": error.to_string(), "held_code": error.held_code()}));
                        json!({"run": format!("{number:04}"), "class": "held", "reason": error.to_string()})
                    }
                };
                match disposed(&store, &dir, number) {
                    Ok(value) => row["disposed"] = json!(value),
                    Err(error) if error.host_fault() => return Err(error),
                    Err(error) => {
                        held_rows.push(json!({"path": format!("{path}/disposition"), "reason": error.to_string(), "held_code": error.held_code()}));
                        row["disposed"] = json!(false);
                        row["reason"] = json!(format!(
                            "{}; {}",
                            row["reason"].as_str().unwrap_or(""),
                            error
                        ));
                    }
                }
                Ok::<_, Error>(row)
            })();
            match result {
                Ok(row) => rows.push(row),
                Err(error) if error.host_fault() => return Err(error),
                Err(error) => {
                    held_rows.push(json!({"path": path, "reason": error.to_string(), "held_code": error.held_code()}));
                    if let Some(number) = number {
                        rows.push(json!({"run": format!("{number:04}"), "class": "held", "reason": error.to_string(), "disposed": false}));
                    }
                }
            }
        }
    }
    rows.sort_by_cached_key(|row| {
        row["run"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
    });
    Ok((Some(store), rows))
}

#[cfg(test)]
#[path = "runs_tests.rs"]
mod tests;
