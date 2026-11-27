//! `resolve` keeps a missing component as written, follows relative and absolute link targets, leaves a
//! link loop and what follows it unresolved, and refuses a final path that loops and links nested past
//! `DEPTH`.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::paths::{DEPTH, resolve};

/// `Scratch` is a directory the test process created itself, with mode 0700, and removes on drop. A name
/// that already exists is left as it is and the next name is tried.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    pub(crate) fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let parent = std::env::temp_dir()
                .canonicalize()
                .expect("the temporary directory resolves");
            let path = parent.join(format!(
                "kestrike-tools-{label}-{}-{at}",
                std::process::id()
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
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

fn tree() -> Scratch {
    let scratch = Scratch::new("paths");
    let base = &scratch.0;
    fs::create_dir_all(base.join("real/deep")).expect("the tree is made");
    symlink("real", base.join("link")).expect("the link is made");
    symlink("loop", base.join("loop")).expect("the loop is made");
    symlink(base.join("real"), base.join("absolute")).expect("the absolute link is made");
    symlink("real/deep", base.join("down")).expect("the deeper link is made");
    symlink("../link", base.join("real/up")).expect("the link to a link is made");
    scratch
}

#[test]
fn links_resolve_as_far_as_the_path_exists() {
    let scratch = tree();
    let base = &scratch.0;
    let at = |rest: &str| PathBuf::from(format!("{}{rest}", base.display()));
    let resolves = |rest: &str| resolve(&at(rest)).expect("resolves");
    assert_eq!(resolves("/link/new/../x"), base.join("real/x"));
    assert_eq!(resolves("/missing/a/./b//"), base.join("missing/a/b"));
    assert_eq!(resolves("/link/.."), *base);
    assert_eq!(resolves("/link"), base.join("real"));
    assert_eq!(resolve(Path::new("/..")).expect("resolves"), Path::new("/"));
    assert_eq!(resolves("/absolute/x"), base.join("real/x"));
    assert_eq!(resolves("/down/.."), base.join("real"));
    assert_eq!(resolves("/real/up/x"), base.join("real/x"));
    assert_eq!(resolves("/link/up/up/x"), base.join("real/x"));
}

#[test]
fn a_link_loop_stays_unresolved_unless_the_final_path_loops() {
    let scratch = tree();
    let base = &scratch.0;
    let at = |rest: &str| PathBuf::from(format!("{}{rest}", base.display()));
    assert_eq!(
        resolve(&at("/loop/../out")).expect("resolves"),
        base.join("out")
    );
    assert_eq!(
        resolve(&at("/loop/../link/x")).expect("resolves"),
        base.join("link/x"),
        "the components after a loop are normalized as written"
    );
    assert_eq!(
        resolve(&at("/loop//../y")).expect("resolves"),
        base.join("y")
    );
    for (looping, named) in [
        ("/loop", "/loop"),
        ("/loop/x", "/loop/x"),
        ("/loop//x", "/loop/x"),
        ("//loop/./x", "/loop/x"),
    ] {
        let error = resolve(&at(looping)).expect_err("a looping final path is refused");
        assert_eq!(
            error.to_string(),
            format!("symlink loop from {}", at(named).display()),
            "{looping}"
        );
    }
}

#[test]
fn links_nested_past_the_depth_are_refused() {
    let scratch = Scratch::new("paths-depth");
    let base = &scratch.0;
    for at in 0..=DEPTH {
        symlink(format!("l{}", at + 1), base.join(format!("l{at}"))).expect("the link is made");
    }
    assert_eq!(
        resolve(&base.join("l1")).expect("a chain of DEPTH links resolves"),
        base.join(format!("l{}", DEPTH + 1))
    );
    let error = resolve(&base.join("l0")).expect_err("a chain past DEPTH is refused");
    assert!(
        error
            .to_string()
            .starts_with(&format!("links nest more than {DEPTH} deep at ")),
        "{error}"
    );
}

#[test]
fn a_relative_path_starts_at_the_working_directory() {
    let here = std::env::current_dir().expect("the working directory reads");
    assert_eq!(resolve(Path::new("")).expect("resolves"), here);
    assert_eq!(
        resolve(Path::new("a/../b")).expect("resolves"),
        here.join("b")
    );
    assert_eq!(
        resolve(Path::new("../b")).expect("resolves"),
        here.parent().expect("the directory has a parent").join("b")
    );
}
