//! The sealed reader contract shares confined reads and durability barriers across stores and views.

use std::path::Path;

use super::{Dir, Error, Name, Opened, Read, Store, Unreadable, View};
use crate::record::{Held, Record, Verified};

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Store {}
    impl Sealed for super::View {}
}

/// Confined reads and barriers use descriptors owned by the reader.
pub(crate) trait ReadStore: sealed::Sealed {
    fn root(&self) -> &Dir;
    fn path(&self) -> &Path;
    fn open_dir(&self, dir: &Dir, name: &Name) -> Result<Option<Dir>, Unreadable>;
    fn open_file(&self, dir: &Dir, name: &Name) -> Result<Option<Opened>, Unreadable>;
    fn read(&self, dir: &Dir, name: &Name, bound: u64) -> Result<Option<Read>, Unreadable>;
    fn list(&self, dir: &Dir, bound: usize) -> Result<Vec<Name>, Error>;
    fn read_record<R: Record>(&self, dir: &Dir, name: &Name) -> Result<Option<Verified<R>>, Held>;
    fn barrier(&self, read: &Read) -> Result<(), Error>;
    fn binding_barrier(&self, read: &Read) -> Result<(), Error>;
    fn sync_file(&self, dir: &Dir, file: &Opened) -> Result<(), Error>;
    fn evidence_digest(
        &self,
        dir: &Dir,
        name: &Name,
        bound: u64,
    ) -> Result<Option<crate::record::Digest>, Unreadable>;
}

macro_rules! reader {
    ($reader:ty, $binding_barrier:expr) => {
        impl ReadStore for $reader {
            fn root(&self) -> &Dir {
                self.root()
            }
            fn path(&self) -> &Path {
                self.path()
            }
            fn open_dir(&self, dir: &Dir, name: &Name) -> Result<Option<Dir>, Unreadable> {
                self.open_dir(dir, name)
            }
            fn open_file(&self, dir: &Dir, name: &Name) -> Result<Option<Opened>, Unreadable> {
                self.open_file(dir, name)
            }
            fn read(&self, dir: &Dir, name: &Name, bound: u64) -> Result<Option<Read>, Unreadable> {
                self.read(dir, name, bound)
            }
            fn list(&self, dir: &Dir, bound: usize) -> Result<Vec<Name>, Error> {
                self.list(dir, bound)
            }
            fn read_record<R: Record>(
                &self,
                dir: &Dir,
                name: &Name,
            ) -> Result<Option<Verified<R>>, Held> {
                self.read_record(dir, name)
            }
            fn evidence_digest(
                &self,
                dir: &Dir,
                name: &Name,
                bound: u64,
            ) -> Result<Option<crate::record::Digest>, Unreadable> {
                self.evidence_digest(dir, name, bound)
            }
            fn sync_file(&self, dir: &Dir, file: &Opened) -> Result<(), Error> {
                self.sync_file(dir, file)
            }
            fn binding_barrier(&self, read: &Read) -> Result<(), Error> {
                ($binding_barrier)(self, read)
            }
            fn barrier(&self, read: &Read) -> Result<(), Error> {
                self.barrier(read)
            }
        }
    };
}
reader!(Store, |_: &Store, _: &Read| Ok(()));
reader!(View, |view: &View, read: &Read| view.barrier(read));

pub(super) fn digest(file: Opened, bound: u64) -> Result<crate::record::Digest, Unreadable> {
    use std::io::Read;
    let mut file = crate::record::Hashing::new(file.take(bound.saturating_add(1)));
    let mut buffer = vec![0; super::publish::COPY_CHUNK];
    let mut size = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size.checked_add(count as u64).ok_or(Unreadable::Oversize)?;
        if size > bound {
            return Err(Unreadable::Oversize);
        }
    }
    Ok(file.finish())
}
