mod admission;
mod calibration;
mod census;
mod cli;
mod collect;
mod configuration;
mod confirm;
mod corpus;
pub mod dispatch;
mod error;
mod findings;
mod freeze;
pub mod known;
mod lineage;
mod minima;
mod probe;
mod projection;
mod reclaim;
mod report;
mod scope;
mod seeds;
mod show;
mod status;
mod storage;
mod sweep;
mod targeted;
mod threads;
pub mod triage;

#[cfg(test)]
mod show_tests;
#[cfg(test)]
pub(crate) mod state_fixture;
#[cfg(test)]
pub(crate) mod status_tests;
#[cfg(test)]
#[path = "campaign_tests.rs"]
mod tests;
#[cfg(test)]
mod threads_tests;

use crate::store::Name;

pub use admission::Outcome;
pub(crate) use admission::{admit, admit_campaign};
pub use cli::run;
pub use configuration::configure;
pub use error::Error;
pub use findings::{dispose, findings};
pub use freeze::Request;
pub use report::report;
pub use show::show;
pub use status::status;
pub use storage::{Root, Storage};

pub(crate) fn name(value: &str) -> Name {
    Name::new(value).expect("campaign record names are valid components")
}

/// The shards of `root`, its listing held at the scan bound and its errors
/// naming `root`.
pub(crate) fn sharded<'a, V: crate::store::ReadStore>(
    view: &'a V,
    root: &'a str,
) -> Result<crate::layout::Shards<'a, V>, Error> {
    crate::layout::shards(view, root).map_err(|error| Error::listing(root, error))
}

/// The entries of `shard`, its listing held at the scan bound on its own
/// and its errors naming the shard.
pub(crate) fn shard_entries(
    view: &impl crate::store::ReadStore,
    shard: &crate::layout::Shard,
) -> Result<Vec<Name>, Error> {
    view.list(&shard.dir, crate::scan_bound())
        .map_err(|error| Error::listing(&shard.path, error))
}

pub(crate) fn text(value: &str) -> Result<crate::record::Text, Error> {
    crate::record::Text::new(value)
        .ok_or_else(|| Error::Rejected("text must be printable ASCII".into()))
}

pub(crate) fn once<R: crate::record::Record + PartialEq>(
    store: &crate::store::Store,
    directory: &crate::store::Dir,
    entry: &str,
    value: &R,
) -> Result<(), Error> {
    let found = match store.read_record::<R>(directory, &name(entry))? {
        Some(found) => found,
        None => {
            store.create_record(directory, &name(entry), value)?;
            store
                .read_record::<R>(directory, &name(entry))?
                .ok_or_else(|| Error::Held("record publication missing".into()))?
        }
    };
    if found.record() != value {
        return Err(Error::Held("record publication differs".into()));
    }
    store.barrier(found.read())?;
    Ok(())
}
