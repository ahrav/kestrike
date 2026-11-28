//! What the FIS controller's cases share: a scratch directory per case, a listing of a directory, the
//! file steps of [`steps`], the clock of [`clock`], and the plane of [`plane`] with its calls of
//! [`calls`], its starts of [`starts`] and its case of [`case`].

#![cfg(target_os = "linux")]

pub(crate) mod calls;
pub(crate) mod case;
pub(crate) mod clock;
pub(crate) mod plane;
pub(crate) mod starts;
pub(crate) mod steps;

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use kestrike_tools::host_stop::Delivered;

/// A directory the case process made with mode 0700 under a fresh name, removed on drop. A name
/// another process took first stays as it is, and the next name is tried.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    pub(crate) fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory resolves");
        loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "kestrike-tools-fis-{label}-{}-{at}",
                std::process::id()
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("{}: {error}", path.display()),
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// `text` with the scratch directory's path written as `<d>`.
    pub(crate) fn norm(&self, text: &str) -> String {
        text.replace(&self.0.display().to_string(), "<d>")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The entries of `directory`, sorted, each with `/` after a directory and `@` after a link.
pub(crate) fn listing(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("the directory lists")
        .map(|entry| {
            let entry = entry.expect("the entry reads");
            let kind = entry.file_type().expect("the entry's type reads");
            let mut name = entry.file_name().to_string_lossy().into_owned();
            if kind.is_dir() {
                name.push('/');
            }
            if kind.is_symlink() {
                name.push('@');
            }
            name
        })
        .collect();
    names.sort();
    names
}

/// A signal record's store of its own, which a case's clock can deliver to; it lives as long as the
/// case process.
pub(crate) fn delivered() -> &'static Delivered {
    Box::leak(Box::new(Delivered::new()))
}
