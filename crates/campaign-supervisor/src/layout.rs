//! Job records and attempt directories are sharded by job id: a job's
//! records live in `jobs/<xx>/` and its attempts in
//! `attempts/<xx>/<id>/<nnnn>/`, where `<xx>` is the first two characters of
//! the job id, two lowercase hex digits for every valid id and the first
//! two characters of any other name. [`shard`] is the one rule every path
//! follows, including the paths handed to workers.

use std::path::PathBuf;

use crate::store::{Dir, Error, Name, ReadStore, Store, Unreadable};

pub(crate) const JOBS: &str = "jobs";
pub(crate) const ATTEMPTS: &str = "attempts";

fn component(value: &str) -> Name {
    Name::new(value).expect("layout components are valid names")
}

/// The shard of job `id`.
pub(crate) fn shard(id: &str) -> Name {
    component(id.get(..2).unwrap_or(id))
}

/// The path of the job-record file `file` of job `id`, relative to the
/// state directory.
pub(crate) fn job_file(id: &str, file: &str) -> PathBuf {
    PathBuf::from(JOBS).join(shard(id).as_str()).join(file)
}

/// The path of attempt directory `number` of job `id`, relative to the
/// state directory.
pub(crate) fn attempt_path(id: &str, number: u64) -> PathBuf {
    PathBuf::from(ATTEMPTS)
        .join(shard(id).as_str())
        .join(id)
        .join(format!("{number:04}"))
}

/// The shard of `root` that holds job `id`, `None` when it is absent.
pub(crate) fn shard_dir(
    view: &impl ReadStore,
    root: &str,
    id: &str,
) -> Result<Option<Dir>, Unreadable> {
    match view.open_dir(view.root(), &component(root))? {
        Some(parent) => view.open_dir(&parent, &shard(id)),
        None => Ok(None),
    }
}

/// The directory of job `id`'s records, `None` when it is absent.
pub(crate) fn jobs(view: &impl ReadStore, id: &str) -> Result<Option<Dir>, Unreadable> {
    shard_dir(view, JOBS, id)
}

/// The directory of job `id`'s attempts, `None` when it is absent.
pub(crate) fn attempts(view: &impl ReadStore, id: &str) -> Result<Option<Dir>, Unreadable> {
    match shard_dir(view, ATTEMPTS, id)? {
        Some(shard) => view.open_dir(&shard, &component(id)),
        None => Ok(None),
    }
}

/// Creates and opens the shard of `root` that holds job `id`.
pub(crate) fn make_shard(store: &Store, root: &str, id: &str) -> Result<Dir, Error> {
    let made = |parent: &Dir, name: Name| -> Result<Dir, Error> {
        store.mkdir(parent, &name)?;
        let gone = Error::Unreadable(Unreadable::Io(std::io::ErrorKind::NotFound.into()));
        store.open_dir(parent, &name)?.ok_or(gone)
    };
    made(&made(store.root(), component(root))?, shard(id))
}

/// The shards of `root`, sorted by name, each opened as the iteration
/// reaches it, so one shard's directory is open at a time; empty when
/// `root` is absent.
///
/// # Errors
///
/// The listing's error; each item carries its open's host fault, and
/// [`Error::Foreign`] for an entry that is no shard directory.
pub(crate) fn shards<'a, V: ReadStore>(view: &'a V, root: &'a str) -> Result<Shards<'a, V>, Error> {
    let parent = view.open_dir(view.root(), &component(root))?;
    let names = match &parent {
        Some(parent) => view.list(parent, crate::scan_bound())?,
        None => Vec::new(),
    };
    Ok(Shards {
        view,
        root,
        parent,
        names: names.into_iter(),
    })
}

/// One shard of a sharded root.
pub(crate) struct Shard {
    pub name: Name,
    pub dir: Dir,
    /// `<root>/<xx>`, relative to the state directory.
    pub path: String,
}

impl Shard {
    /// Whether job `id`'s entries belong in this shard.
    pub(crate) fn holds(&self, id: &str) -> bool {
        shard(id) == self.name
    }
}

/// The shards of one sharded root, in name order.
pub(crate) struct Shards<'a, V> {
    view: &'a V,
    root: &'a str,
    parent: Option<Dir>,
    names: std::vec::IntoIter<Name>,
}

impl<V: ReadStore> Iterator for Shards<'_, V> {
    type Item = Result<Shard, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let name = self.names.next()?;
        let parent = self.parent.as_ref()?;
        let path = format!("{}/{}", self.root, name.as_str());
        let hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
        if name.as_str().len() != 2 || !name.as_str().bytes().all(hex) {
            return Some(Err(Error::Foreign(path)));
        }
        Some(match self.view.open_dir(parent, &name) {
            Ok(Some(dir)) => Ok(Shard { name, dir, path }),
            Err(error) if error.faulted() => Err(error.into()),
            _ => Err(Error::Foreign(path)),
        })
    }
}

#[cfg(test)]
#[path = "layout_tests.rs"]
mod tests;
