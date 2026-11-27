use std::os::unix::fs::PermissionsExt;

use crate::temp_dir::{TempDirError, make_temp_dir};

#[test]
fn a_new_directory_takes_eight_letters_and_mode_0700() {
    let scratch = crate::paths::tests::Scratch::new("rundir");
    let made = make_temp_dir("worktree-", &scratch.0).expect("the directory is made");
    let name = made
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a UTF-8 name");
    let letters = name.strip_prefix("worktree-").expect("the prefix stays");
    assert_eq!(letters.len(), 8, "{name}");
    assert!(
        letters
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
        "{name}"
    );
    let mode = std::fs::metadata(&made)
        .expect("it exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn a_parent_that_is_a_file_fails_the_create_with_the_path_and_errno() {
    let scratch = crate::paths::tests::Scratch::new("rundir-file");
    let file = scratch.0.join("file");
    std::fs::write(&file, "x").expect("written");
    let Err(TempDirError::Create(error)) = make_temp_dir("worktree-", &file) else {
        panic!("a file is no parent");
    };
    assert_eq!(error.error().raw_os_error(), Some(libc::ENOTDIR));
    let name = error
        .path()
        .strip_prefix(&file)
        .expect("under the file")
        .to_str()
        .expect("UTF-8");
    assert_eq!(
        name.strip_prefix("worktree-").map(str::len),
        Some(8),
        "{name}"
    );
}
