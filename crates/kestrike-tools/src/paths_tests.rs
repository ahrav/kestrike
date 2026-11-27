//! `resolve` keeps a missing component as written and refuses a symlink loop.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use crate::paths::resolve;

fn tree() -> PathBuf {
    let base = std::env::temp_dir().join(format!("kestrike-tools-paths-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("real")).expect("the tree is made");
    symlink("real", base.join("link")).expect("the link is made");
    symlink("loop", base.join("loop")).expect("the loop is made");
    base.canonicalize().expect("the tree resolves")
}

#[test]
fn links_resolve_as_far_as_the_path_exists() {
    let base = tree();
    let at = |rest: &str| PathBuf::from(format!("{}{rest}", base.display()));
    assert_eq!(
        resolve(&at("/link/new/../x")).expect("resolves"),
        base.join("real/x")
    );
    assert_eq!(
        resolve(&at("/missing/a/./b//")).expect("resolves"),
        base.join("missing/a/b")
    );
    assert_eq!(resolve(&at("/link/..")).expect("resolves"), base);
    assert_eq!(resolve(&at("/link")).expect("resolves"), base.join("real"));
    assert_eq!(resolve(Path::new("/..")).expect("resolves"), Path::new("/"));
    assert!(
        resolve(&at("/loop/x")).is_err(),
        "a link to itself is a loop"
    );
    fs::remove_dir_all(&base).expect("the tree is removed");
}

#[test]
fn a_relative_path_starts_at_the_working_directory() {
    let here = std::env::current_dir().expect("the working directory reads");
    assert_eq!(resolve(Path::new("")).expect("resolves"), here);
    assert_eq!(
        resolve(Path::new("a/../b")).expect("resolves"),
        here.join("b")
    );
}
