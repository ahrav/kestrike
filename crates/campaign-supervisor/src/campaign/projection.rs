//! Projection records recoverable failures as held rows and propagates scan bounds and host faults.

use super::{Error, name};
use crate::store::{Dir, ReadStore};
use serde_json::{Value, json};

pub(super) fn root(
    view: &impl ReadStore,
    entry: &str,
    rows: &mut Vec<Value>,
) -> Result<Option<Dir>, Error> {
    match view.open_dir(view.root(), &name(entry)) {
        Ok(directory) => Ok(directory),
        Err(error) => {
            held(rows, entry, error.into())?;
            Ok(None)
        }
    }
}

/// Runs `each` on every shard of the sharded root `entry`, one shard open
/// at a time, with a failed listing or open, and an entry that is not a
/// shard, recorded as a held row of `entry`.
pub(super) fn each_shard(
    view: &impl ReadStore,
    entry: &str,
    rows: &mut Vec<Value>,
    mut each: impl FnMut(crate::layout::Shard, &mut Vec<Value>) -> Result<(), Error>,
) -> Result<(), Error> {
    let shards = match super::sharded(view, entry) {
        Ok(shards) => shards,
        Err(error) => return held(rows, entry, error),
    };
    for shard in shards {
        match shard {
            Ok(shard) => each(shard, rows)?,
            Err(error) => held(rows, entry, error.into())?,
        }
    }
    Ok(())
}

pub(super) fn held(rows: &mut Vec<Value>, path: &str, error: Error) -> Result<(), Error> {
    if error.at_scan_bound() || error.host_fault() {
        return Err(error);
    }
    let row = json!({"path": path, "reason": error.to_string(), "held_code": error.held_code()});
    if path != "probes" || !rows.contains(&row) {
        rows.push(row);
    }
    Ok(())
}

pub(super) fn entries(
    view: &impl ReadStore,
    directory: &crate::store::Dir,
    path: &str,
    rows: &mut Vec<Value>,
) -> Result<Vec<crate::store::Name>, Error> {
    match view.list(directory, crate::scan_bound()) {
        Ok(entries) => Ok(entries),
        Err(error) => {
            held(rows, path, Error::listing(path, error))?;
            Ok(Vec::new())
        }
    }
}
