//! The storage headroom of a state directory: the fullest shard's count for
//! jobs and attempts, top-level counts for other roots, against the scan
//! bound, and the free
//! bytes and inodes measured on its filesystem. `show` and the dispatch
//! report print the headroom measurement.

use std::collections::BTreeMap;

use serde::Serialize;

use super::{Error, name};
use crate::store::ReadStore;

/// The roots whose listings grow with the campaign.
const ROOTS: [&str; 5] = ["attempts", "findings", "jobs", "probes", "triage"];

/// One measurement of a state directory's headroom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Storage {
    /// Each existing root by name.
    pub roots: BTreeMap<String, Root>,
    /// The bytes available to unprivileged users on the state filesystem.
    pub free_bytes: u64,
    /// The inodes available to unprivileged users on the state filesystem.
    pub free_inodes: u64,
}

/// One root's top-level entry count and the bound its listing is held at;
/// for the sharded `jobs` and `attempts`, the count of the fullest shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Root {
    pub entries: usize,
    pub bound: usize,
}

/// Lists each root and every jobs and attempts shard, then measures
/// filesystem free space. An overflow
/// returns a root-named [`Error::Bound`]; other measurement errors propagate.
pub(crate) fn measure(view: &impl ReadStore) -> Result<Storage, Error> {
    let bound = crate::scan_bound();
    let mut roots = BTreeMap::new();
    for root in ROOTS {
        let Some(directory) = view.open_dir(view.root(), &name(root))? else {
            continue;
        };
        let entries = if [crate::layout::JOBS, crate::layout::ATTEMPTS].contains(&root) {
            let mut fullest = 0;
            for shard in crate::campaign::sharded(view, root)? {
                if matches!(shard, Err(crate::store::Error::Foreign(_))) {
                    continue;
                }
                fullest = fullest.max(super::shard_entries(view, &shard?)?.len());
            }
            fullest
        } else {
            view.list(&directory, bound)
                .map_err(|error| Error::listing(root, error))?
                .len()
        };
        roots.insert(root.to_owned(), Root { entries, bound });
    }
    let (free_bytes, free_inodes, _) = view.root().free_space()?;
    Ok(Storage {
        roots,
        free_bytes,
        free_inodes,
    })
}
