use std::io;

use super::{Dir, Error, Name, Store, Unreadable};
use crate::step::{self, Step};
use crate::sys;

pub const EVIDENCE_BOUND: usize = 4_096;

pub(crate) const ATTEMPT_RECORDS: [&str; 8] = [
    "attempt",
    "reservation",
    "intent",
    "started",
    "bound",
    "finished",
    "captured",
    "reclaimed",
];

impl Store {
    pub(crate) fn evidence_barrier(&self, root: &Dir, bound: usize) -> Result<Dir, Error> {
        self.guard(root, || {
            let mut remaining = bound.min(EVIDENCE_BOUND);
            let mut stack = vec![(b".".to_vec(), false)];
            while let Some((path, visited)) = stack.pop() {
                let directory = open_path(root, &path)?;
                if visited {
                    step::call(Step::Sync, || directory.file.sync_all())?;
                    step::last(Step::Close, || sys::close(directory.file))?;
                    continue;
                }
                let root_directory = path == b".";
                let allowance = remaining.saturating_add(if root_directory {
                    ATTEMPT_RECORDS.len()
                } else {
                    0
                });
                let entries = super::read::entries(&directory, allowance)?;
                stack.push((path.clone(), true));
                for entry in entries {
                    let component = std::ffi::CString::new(entry.clone())
                        .expect("directory entries contain no NUL");
                    let file = step::call(Step::Open, || {
                        sys::open_beneath(
                            &directory.file,
                            &component,
                            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
                            0,
                        )
                    })
                    .map_err(Unreadable::from)?;
                    let metadata = step::call(Step::Stat, || file.metadata())?;
                    let controller_file = root_directory
                        && metadata.is_file()
                        && ATTEMPT_RECORDS.iter().any(|name| name.as_bytes() == entry);
                    if !controller_file {
                        remaining = remaining.checked_sub(1).ok_or(Error::ScanBound)?;
                    }
                    if metadata.is_dir() {
                        let mut child = path.clone();
                        child.push(b'/');
                        child.extend(entry);
                        stack.push((child, false));
                    } else if metadata.is_file() {
                        step::call(Step::Sync, || file.sync_all())?;
                    } else {
                        return Err(Error::Unreadable(Unreadable::NotRegular));
                    }
                    step::last(Step::Close, || sys::close(file))?;
                }
                step::last(Step::Close, || sys::close(directory.file))?;
            }
            step::call(Step::Evidence, || Ok::<_, io::Error>(()))?;
            super::dir::open_dir(root, c".").map_err(Error::Unreadable)
        })
    }
}

impl Store {
    pub(crate) fn evidence_digest(
        &self,
        directory: &Dir,
        name: &Name,
        bound: u64,
    ) -> Result<Option<crate::record::Digest>, Unreadable> {
        self.open_file(directory, name)?
            .map(|file| super::reader::digest(file, bound))
            .transpose()
    }
}

fn open_path(root: &Dir, path: &[u8]) -> Result<Dir, Error> {
    let mut current = super::dir::open_dir(root, c".").map_err(Error::Unreadable)?;
    for component in path
        .split(|byte| *byte == b'/')
        .filter(|component| *component != b".")
    {
        let component = std::ffi::CString::new(component).expect("entry names contain no NUL");
        let next = super::dir::open_dir(&current, &component).map_err(Error::Unreadable)?;
        step::last(Step::Close, || sys::close(current.file))?;
        current = next;
    }
    Ok(current)
}

impl super::View {
    pub(crate) fn evidence_digest(
        &self,
        directory: &Dir,
        name: &Name,
        bound: u64,
    ) -> Result<Option<crate::record::Digest>, Unreadable> {
        let Some(file) = self.open_file(directory, name)? else {
            return Ok(None);
        };
        self.sync_file(directory, &file).map_err(|error| {
            Unreadable::Io(match error {
                super::Error::Io(error) => error,
                error => std::io::Error::other(error),
            })
        })?;
        super::reader::digest(file, bound)
            .map(Some)
            .inspect_err(|error| self.note_unreadable(error))
    }
}

/// All entries count toward the bound; housekeeping names stay with the store.
pub(crate) fn retained_entries(dir: &Dir, bound: usize) -> Result<Option<Vec<Name>>, Error> {
    let entries = super::read::entries(dir, bound)?;
    let marked = entries.iter().any(|entry| {
        super::HOUSEKEEPING_ENTRIES
            .iter()
            .any(|name| name.to_bytes() == entry)
    });
    if marked && !super::publish::removable_marks(dir)? {
        return Ok(None);
    }
    super::read::names(entries, true).map(Some)
}
