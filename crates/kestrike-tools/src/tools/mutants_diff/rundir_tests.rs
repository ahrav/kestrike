use std::os::unix::fs::PermissionsExt;

use super::rundir::{make_temp_dir, utc_stamp_at};

#[test]
fn the_stamp_is_the_utc_calendar_time_of_its_seconds() {
    for (seconds, stamp) in [
        (0, "19700101T000000Z-"),
        (951_782_400, "20000229T000000Z-"),
        (1_709_251_200, "20240301T000000Z-"),
        (1_735_689_599, "20241231T235959Z-"),
        (4_107_542_399, "21000228T235959Z-"),
    ] {
        assert_eq!(
            utc_stamp_at(seconds),
            stamp,
            "time.strftime('%Y%m%dT%H%M%SZ-', time.gmtime({seconds}))"
        );
    }
}

#[test]
fn a_new_directory_takes_eight_letters_and_mode_0700() {
    let parent = std::env::temp_dir().join(format!("kestrike-tools-rundir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    std::fs::create_dir_all(&parent).expect("the parent is made");
    let made = make_temp_dir("worktree-", &parent).expect("the directory is made");
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
    std::fs::remove_dir_all(&parent).expect("the parent is removed");
}
