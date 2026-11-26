use super::{Dir, Error, Store, Unreadable};
use crate::step::{self, Step};
use crate::sys;

#[derive(Debug, Clone, Copy)]
pub struct Usage {
    pub bytes: u64,
    pub inodes: u64,
    pub free_bytes: u64,
    pub free_inodes: u64,
    pub fragment_bytes: std::num::NonZeroU64,
}

impl Dir {
    /// `free_space` returns the bytes and inodes available to unprivileged
    /// users on this directory's filesystem (`f_bavail`, `f_favail`) and its
    /// fragment size.
    ///
    /// # Errors
    ///
    /// `free_space` returns an error if `fstatvfs` fails or the fragment size
    /// is zero.
    pub(crate) fn free_space(&self) -> std::io::Result<(u64, u64, std::num::NonZeroU64)> {
        let measured = step::call(Step::Stat, || sys::free_space(&self.file))?;
        let (free_bytes, free_inodes) = step::space((measured.0, measured.1))?;
        Ok((free_bytes, free_inodes, measured.2))
    }

    pub(crate) fn usage(&self, mut bound: usize) -> Result<Usage, Error> {
        let mut usage = Usage {
            bytes: 0,
            inodes: 0,
            free_bytes: 0,
            free_inodes: 0,
            fragment_bytes: std::num::NonZeroU64::new(1).unwrap(),
        };
        Store::measure(self, &mut bound, &mut usage, 0)?;
        Ok(usage)
    }
}

impl Store {
    pub fn usage(&self, bound: usize) -> Result<Usage, Error> {
        let (free_bytes, free_inodes, fragment_bytes) = self.root().free_space()?;
        let mut usage = Usage {
            bytes: 0,
            inodes: 0,
            free_bytes,
            free_inodes,
            fragment_bytes,
        };
        let mut left = bound;
        Self::measure(self.root(), &mut left, &mut usage, 0)?;
        Ok(usage)
    }

    fn measure(
        directory: &Dir,
        left: &mut usize,
        usage: &mut Usage,
        depth: usize,
    ) -> Result<(), Error> {
        if depth == 64 {
            return Err(Error::DepthBound);
        }
        let mut entries = match super::read::entries(directory, *left) {
            Err(Error::Io(error)) if depth > 0 && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            result => result?,
        };
        entries.sort();
        for bytes in entries {
            let name = std::ffi::CString::new(bytes)
                .map_err(|_| Error::Foreign("invalid census entry".into()))?;
            *left = left.checked_sub(1).ok_or(Error::ScanBound)?;
            let file = match step::call(Step::Open, || {
                sys::open_beneath(&directory.file, &name, libc::O_PATH | libc::O_NOFOLLOW, 0)
            }) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                result => result?,
            };
            let metadata = step::call(Step::Stat, || file.metadata())?;
            usage.inodes = usage.inodes.saturating_add(1);
            if metadata.is_dir() {
                match super::dir::open_dir(directory, &name) {
                    Ok(child) => Self::measure(&child, left, usage, depth + 1)?,
                    Err(Unreadable::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(Error::Unreadable(error)),
                }
            } else if metadata.is_file() {
                usage.bytes = usage.bytes.saturating_add(metadata.len());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fixture::{Case, processes};
    use std::fs;
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};

    #[test]
    fn metadata_census_counts_ipc_and_unreadable_entries_without_opening_their_data() {
        let _processes = processes();
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let before = store.usage(crate::scan_bound()).unwrap();
        let socket = UnixListener::bind(case.state.join("socket")).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(case.state.join("fifo"))
                .status()
                .unwrap()
                .success()
        );
        fs::write(case.state.join("opaque"), b"12345").unwrap();
        fs::set_permissions(case.state.join("opaque"), fs::Permissions::from_mode(0o0)).unwrap();
        let after = store.usage(crate::scan_bound()).unwrap();
        assert_eq!(after.inodes, before.inodes + 3);
        assert_eq!(after.bytes, before.bytes + 5);
        drop(socket);
    }

    #[test]
    fn a_descendant_removed_after_open_is_skipped_and_other_listing_errors_hold() {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        fs::create_dir(case.state.join("child")).unwrap();
        let child = store
            .open_dir(store.root(), &crate::store::Name::new("child").unwrap())
            .unwrap()
            .unwrap();
        fs::remove_dir(case.state.join("child")).unwrap();
        let mut usage = Usage {
            bytes: 0,
            inodes: 0,
            free_bytes: 0,
            free_inodes: 0,
            fragment_bytes: std::num::NonZeroU64::new(1).unwrap(),
        };
        Store::measure(&child, &mut 10, &mut usage, 1).unwrap();
        assert_eq!(usage.inodes, 0);
        assert!(Store::measure(&child, &mut 10, &mut usage, 0).is_err());
    }
}
