//! The score's write: through a new staging file beside the target, renamed over it, with mode 0666
//! less the umask; a write that fails leaves no staging file. And the removal of a run's directory.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use std::io::Write;

use super::{publish, staging_with};
use crate::paths::tests::Scratch;
use crate::plants::run::remove;

fn umask() -> u32 {
    let status = fs::read_to_string("/proc/self/status").expect("the status reads");
    let line = status
        .lines()
        .find(|line| line.starts_with("Umask:"))
        .expect("a Umask line");
    u32::from_str_radix(line.trim_start_matches("Umask:").trim(), 8).expect("an octal umask")
}

fn staged(dir: &std::path::Path) -> usize {
    fs::read_dir(dir)
        .expect("lists")
        .filter(|entry| {
            entry
                .as_ref()
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".score.json.")
        })
        .count()
}

/// A link at the score's path is replaced and its target stays; the score takes mode 0666 less the
/// umask, and no staging file stays.
#[test]
fn a_score_replaces_a_link_and_takes_its_mode() {
    let scratch = Scratch::new("publish");
    let (target, elsewhere) = (scratch.0.join("score.json"), scratch.0.join("elsewhere"));
    fs::write(&elsewhere, "kept\n").expect("written");
    symlink(&elsewhere, &target).expect("linked");
    publish(&target, "{}\n").expect("the score is written");
    assert_eq!(fs::read_to_string(&target).expect("reads"), "{}\n");
    assert_eq!(fs::read_to_string(&elsewhere).expect("reads"), "kept\n");
    let mode = fs::symlink_metadata(&target)
        .expect("stats")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o666 & !umask());
    assert_eq!(staged(&scratch.0), 0);
}

/// A staging name that is taken, by a regular file or by a link, is left as it is, and the next name
/// drawn takes the staging file.
#[test]
fn a_taken_staging_name_is_left_as_it_is() {
    let scratch = Scratch::new("publish-taken");
    let target = scratch.0.join("score.json");
    let elsewhere = scratch.0.join("elsewhere");
    fs::write(&elsewhere, "outside\n").expect("written");
    fs::write(scratch.0.join(".score.json.aaaaaaaa"), "taken\n").expect("written");
    symlink(&elsewhere, scratch.0.join(".score.json.bbbbbbbb")).expect("linked");
    let mut names = b"abc".iter().copied();
    let (path, mut file) = staging_with(&target, |letters| {
        letters.fill(names.next().expect("three names are drawn at most"));
        Ok(())
    })
    .expect("a free name is found");
    assert_eq!(path, scratch.0.join(".score.json.cccccccc"));
    file.write_all(b"staged\n").expect("written");
    assert_eq!(
        fs::read_to_string(scratch.0.join(".score.json.aaaaaaaa")).expect("reads"),
        "taken\n"
    );
    let link = scratch.0.join(".score.json.bbbbbbbb");
    assert!(
        fs::symlink_metadata(&link)
            .expect("stats")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&elsewhere).expect("reads"), "outside\n");
    assert_eq!(fs::read_to_string(&path).expect("reads"), "staged\n");
}

/// A directory at the score's path fails the write, which leaves the directory and no staging file.
#[test]
fn a_score_that_cannot_be_renamed_leaves_no_staging_file() {
    let scratch = Scratch::new("publish-blocked");
    let target = scratch.0.join("score.json");
    fs::create_dir(&target).expect("made");
    let error = publish(&target, "{}\n").expect_err("a directory takes no score");
    assert!(error.to_string().contains("score.json"), "{error}");
    assert!(target.is_dir());
    assert_eq!(staged(&scratch.0), 0);
}

/// The removal goes past an entry it cannot remove, removes the rest, and leaves a link at its path.
#[test]
fn a_removal_goes_past_what_it_cannot_remove_and_leaves_a_link() {
    let scratch = Scratch::new("remove");
    let tree = scratch.0.join("tree");
    fs::create_dir_all(tree.join("pinned")).expect("made");
    fs::create_dir_all(tree.join("free")).expect("made");
    fs::write(tree.join("pinned/file"), "held").expect("written");
    fs::write(tree.join("free/file"), "free").expect("written");
    fs::set_permissions(tree.join("pinned"), fs::Permissions::from_mode(0o500)).expect("chmod");
    let link = scratch.0.join("link");
    symlink(&tree, &link).expect("linked");
    remove(&link);
    assert!(
        fs::symlink_metadata(&link).is_ok() && tree.join("free").exists(),
        "a link stays as it is"
    );
    remove(&tree);
    // SAFETY: `geteuid` takes no argument and always succeeds.
    let root = unsafe { libc::geteuid() } == 0;
    assert!(!tree.join("free").exists());
    assert_eq!(tree.join("pinned/file").exists(), !root);
    fs::set_permissions(tree.join("pinned"), fs::Permissions::from_mode(0o700)).ok();
}
