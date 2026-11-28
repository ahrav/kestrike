//! The cases of the `weaken-orderings` tool that start the built binary: the `check` command on the
//! checkout and on trees that lack its inputs, the command reader's usage and help, and the `run` command
//! over a clone of the checkout.
#![cfg(target_os = "linux")]

mod check;
mod drift;
mod fixture;
mod genmc;
mod kept;
mod loom;
mod refusals;
mod signals;
mod standins;

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");

/// The checkout's top level.
pub fn top() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout resolves")
}

/// A directory of mode 0700 that this case made under a name of its own in `CARGO_TARGET_TMPDIR`; a
/// taken name is left as it is, and the directory is removed when the case ends.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let parent = Path::new(env!("CARGO_TARGET_TMPDIR"));
        loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("weaken-{label}-{}-{at}", std::process::id()));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("{}: {error}", path.display()),
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `tool` starts the binary as `weaken-orderings` with the checkout `top` and `args`, in `cwd`.
pub fn tool(top: &Path, args: &[&str], cwd: &Path) -> Output {
    Command::new(BINARY)
        .arg(top)
        .arg("weaken-orderings")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("the binary starts")
}
