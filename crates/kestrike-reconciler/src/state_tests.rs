use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use kestrike::storage::store::{Watermark, WatermarkLog};

use super::{State, StateError, WATERMARK};
use crate::fixture::Scratch;

#[test]
fn init_records_the_empty_watermark_once() {
    let scratch = Scratch::new("init");
    let path = scratch.path().join("state");
    let state = State::create(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    state.init().unwrap();
    let before = fs::read(path.join(WATERMARK)).unwrap();
    assert!(matches!(state.init(), Err(StateError::Initialized)));
    assert_eq!(fs::read(path.join(WATERMARK)).unwrap(), before);
    assert_eq!(state.log().unwrap().load().unwrap(), Watermark::default());
}

#[test]
fn a_second_open_is_refused_while_the_first_holds_the_lock() {
    let scratch = Scratch::new("lock");
    let path = scratch.path().join("state");
    let first = State::create(&path).unwrap();
    assert!(matches!(State::open(&path), Err(StateError::Busy)));
    drop(first);
    State::open(&path).unwrap();
}

#[test]
fn the_watermark_log_holds_the_lock_until_it_drops() {
    let scratch = Scratch::new("log-lock");
    let path = scratch.path().join("state");
    let state = State::create(&path).unwrap();
    state.init().unwrap();
    let log = state.log().unwrap();
    assert!(matches!(State::open(&path), Err(StateError::Busy)));
    drop(log);
    State::open(&path).unwrap();
}

/// After path rebinding, `init` and the log still target the locked directory, and the replacement keeps its
/// contents.
#[test]
fn state_operations_reach_the_locked_directory_after_its_path_is_rebound() {
    let scratch = Scratch::new("rebound");
    let path = scratch.path().join("state");
    let state = State::create(&path).unwrap();
    state.init().unwrap();
    let aside = scratch.path().join("aside");
    fs::rename(&path, &aside).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path.join("planted"), b"planted").unwrap();
    assert!(matches!(state.init(), Err(StateError::Initialized)));
    let mut log = state.log().unwrap();
    assert_eq!(log.reload().unwrap(), Watermark::default());
    log.record(&Watermark::default()).unwrap();
    assert!(aside.join(WATERMARK).exists());
    assert!(!path.join(WATERMARK).exists());
    assert_eq!(fs::read(path.join("planted")).unwrap(), b"planted");
}

#[test]
fn a_directory_without_a_watermark_is_uninitialized() {
    let scratch = Scratch::new("uninitialized");
    let path = scratch.path().join("state");
    let state = State::create(&path).unwrap();
    assert!(matches!(state.log(), Err(StateError::Uninitialized)));
    let missing = scratch.path().join("missing");
    assert!(matches!(State::open(&missing), Err(StateError::Io(_))));
}

/// `init` succeeds with a leftover `watermark.tmp`. With the watermark removed and `status.json` present, `init`
/// refuses and `status.json` keeps its bytes.
#[test]
fn init_refuses_a_used_directory_without_a_watermark() {
    let scratch = Scratch::new("used");
    let path = scratch.path().join("state");
    let state = State::create(&path).unwrap();
    fs::write(path.join("watermark.tmp"), b"partial").unwrap();
    state.init().unwrap();
    fs::remove_file(path.join(WATERMARK)).unwrap();
    fs::write(path.join("status.json"), b"{}").unwrap();
    assert!(matches!(state.init(), Err(StateError::Used)));
    assert!(!path.join(WATERMARK).exists());
    assert_eq!(fs::read(path.join("status.json")).unwrap(), b"{}");
}

/// `mkfs.ext4` creates `lost+found` in the file system's root, so a fresh ext4 mount point fails `init`'s
/// empty-directory check.
#[test]
fn init_refuses_a_first_directory_that_holds_another_entry_and_names_both_remedies() {
    let scratch = Scratch::new("lost-found");
    let path = scratch.path().join("state");
    let state = State::create(&path).unwrap();
    fs::create_dir(path.join("lost+found")).unwrap();
    let error = state.init().unwrap_err();
    assert!(matches!(error, StateError::Used), "{error:?}");
    let message = error.to_string();
    assert!(message.contains("restore the watermark"), "{message}");
    assert!(message.contains("empty directory"), "{message}");
    assert!(!path.join(WATERMARK).exists());
}

/// `O_NOFOLLOW` applies only to the final path component. On Linux, a trailing `/` or `/.` makes path resolution
/// follow the preceding symlink.
#[test]
fn a_symlink_at_the_state_path_is_refused_however_its_name_ends() {
    let scratch = Scratch::new("link-endings");
    let target = scratch.path().join("target");
    drop(State::create(&target).unwrap());
    let link = scratch.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let ended = |path: &Path, ending: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(ending);
        PathBuf::from(name)
    };
    for ending in ["", "/", "//", "/.", "/./"] {
        let path = ended(&link, ending);
        assert!(
            matches!(State::open(&path), Err(StateError::Io(_))),
            "open {ending:?}"
        );
        let created = State::create(&path).and_then(|state| state.init());
        assert!(
            matches!(created, Err(StateError::Io(_))),
            "create {ending:?}: {created:?}"
        );
        assert!(!target.join(WATERMARK).exists(), "{ending:?}");
        State::open(&ended(&target, ending)).unwrap();
    }
}

#[test]
fn a_directory_open_to_its_group_is_refused() {
    let scratch = Scratch::new("shared");
    let path = scratch.path().join("state");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(State::create(&path), Err(StateError::Shared)));
    let link = scratch.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(matches!(State::open(&link), Err(StateError::Io(_))));
}

/// Under `ProtectSystem=strict`, the shipped unit's `ReadWritePaths=` permits writes to the state directory while
/// preserving the owner and mode that [`State::open`] checks.
#[test]
fn the_unit_leaves_the_state_directory_owner_and_mode_to_the_open_check() {
    let settings: Vec<(&str, &str)> = include_str!("../kestrike-reconciler.service")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .collect();
    let repaired: Vec<_> = settings
        .iter()
        .filter(|(name, _)| matches!(*name, "StateDirectory" | "StateDirectoryMode"))
        .collect();
    assert!(repaired.is_empty(), "{repaired:?}");
    assert!(settings.contains(&("ProtectSystem", "strict")));
    assert!(
        settings.contains(&("ReadWritePaths", "-/var/lib/kestrike-reconciler")),
        "{settings:?}"
    );
}
