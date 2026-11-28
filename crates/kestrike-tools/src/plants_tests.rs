//! The record's value tests: `natural` holds for a JSON integer of at least its bound, and a boolean or a
//! float is none; `count` holds for a positive integer; `text` holds for a string with a code point outside
//! the whitespace `str.isspace` takes. The status readers `unlisted_replay` and `held_suspects` on the
//! statuses the judgment cannot reach. `Opens`, the watch by which the tests of this library's children
//! see a start.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;

use crate::json::{Value, parse};
use crate::plants::values::{count, natural, text};

/// `Opens` watches the file that a path names when the watch is added, and queues a record for each
/// open of that file by any process. An `exec` of the file opens it, and the start of a child returns
/// only after that `exec`, so the queue shows a start of the file, also the start of a child that a
/// signal kills before it runs an instruction. A file that takes the watched file's name later is
/// outside the watch.
pub(super) struct Opens(File);

impl Opens {
    pub(super) fn of(path: &Path) -> Self {
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a name");
        // SAFETY: the call takes two flags and no pointer.
        let queue = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(
            queue >= 0,
            "the watch's setup has no inotify instance: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: `queue` is an open descriptor that this value alone owns.
        let queue = unsafe { File::from_raw_fd(queue) };
        // SAFETY: `queue` is open and `name` is a NUL-terminated path that outlives the call.
        let watch =
            unsafe { libc::inotify_add_watch(queue.as_raw_fd(), name.as_ptr(), libc::IN_OPEN) };
        assert!(
            watch >= 0,
            "the watch's setup adds no watch of {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        Self(queue)
    }

    /// `inert` writes at `path` a program that exits 0 with no output, watches it and leaves it
    /// executable and unreadable. Its interpreter opens no script, so a record of this watch is an
    /// `exec` of the program or an open by a process that needs no read permission.
    pub(super) fn inert(path: &Path) -> Self {
        crate::fixtures::tests::script(path, "#!/bin/true\n");
        let opens = Self::of(path);
        let execute = std::os::unix::fs::PermissionsExt::from_mode(0o100);
        std::fs::set_permissions(path, execute).expect("the program is left executable alone");
        opens
    }

    /// `any` takes the queued records and holds when the queue held one since the last call.
    pub(super) fn any(&self) -> bool {
        let mut records = [0_u8; 4096];
        match (&self.0).read(&mut records) {
            Ok(0) => panic!("a read of the queue takes a record or fails"),
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(error) => panic!("the queue is read: {error}"),
        }
    }
}

fn value(json: &str) -> Value {
    parse(json).expect("a JSON value")
}

#[test]
fn natural_and_count_take_integers_alone() {
    let rows: &[(&str, u64, bool, bool)] = &[
        ("0", 0, true, false),
        ("1", 0, true, true),
        ("-1", 0, false, false),
        ("1.0", 0, false, false),
        ("true", 0, false, false),
        ("\"1\"", 0, false, false),
        ("null", 0, false, false),
        ("5", 6, false, true),
        ("6", 6, true, true),
        ("123456789012345678901234567890", 6, true, true),
    ];
    for &(json, least, holds, counted) in rows {
        assert_eq!(
            natural(&value(json), least),
            holds,
            "natural({json}, {least})"
        );
        assert_eq!(count(&value(json)), counted, "count({json})");
    }
}

#[test]
fn text_is_a_string_with_a_code_point_outside_the_whitespace() {
    let rows: &[(&str, bool)] = &[
        ("\"a\"", true),
        ("\" a \"", true),
        ("\"\"", false),
        ("\" \\t\\n\"", false),
        ("\"\\u001c\\u00a0\\u3000\"", false),
        ("\"\\u200b\"", true),
        ("\"\\udc80\"", true),
        ("1", false),
        ("[\"a\"]", false),
    ];
    for &(json, holds) in rows {
        assert_eq!(text(&value(json)), holds, "text({json})");
    }
}

/// `unlisted_replay` on a status and the lines of each profile and key: every reason it gives, in its
/// order of checks, and `None` where the status accounts for every suspect of the profile. A truthy
/// `profiles` of another shape and a sum by key of more digits than an integer holds are the run's
/// failure, and a total of another number type than an integer reads as unequal to the sum by key.
#[test]
fn a_status_may_hide_a_differing_replay_for_each_of_its_reasons() {
    use std::collections::BTreeMap;

    use crate::plants::status::unlisted_replay;
    use crate::text::Text;

    let named = "`campaign sweep-status` names no profile smoke";
    let no_keys = "`campaign sweep-status` gives smoke no count of its suspects by key";
    const NINES: &str = "two keys of the most nines an integer holds";
    type Lines = &'static [(&'static str, &'static str, usize)];
    type Reason = Result<Option<&'static str>, &'static str>;
    let rows: &[(&str, Lines, Reason)] = &[
        (r#"{"profiles": {}}"#, &[], Ok(Some(named))),
        (r#"{"profiles": null}"#, &[], Ok(Some(named))),
        (r#"{"profiles": []}"#, &[], Ok(Some(named))),
        (r#"{"profiles": {"smoke": [1]}}"#, &[], Ok(Some(named))),
        (
            r#"{"profiles": {"smoke": {"suspects": 1}}}"#,
            &[],
            Ok(Some(no_keys)),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 1, "suspect_keys": []}}}"#,
            &[],
            Ok(Some(no_keys)),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 1, "suspect_keys": {"a": 1.0}}}}"#,
            &[],
            Ok(Some(no_keys)),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 1.0, "suspect_keys": {"a": 1}}}}"#,
            &[],
            Ok(Some(
                "`campaign sweep-status` counts 1.0 suspects of smoke and 1 by key",
            )),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": null, "suspect_keys": {}}}}"#,
            &[],
            Ok(Some(
                "`campaign sweep-status` counts None suspects of smoke and 0 by key",
            )),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 3, "suspect_keys": {"b": 1, "a": 2}}}}"#,
            &[("smoke", "b", 2), ("smoke", "a", 3)],
            Ok(Some(
                "`suspects.jsonl` lists 3 suspects of smoke under `a` and `campaign sweep-status` counts 2",
            )),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 3, "suspect_keys": {"b": 1, "a": 2}}}}"#,
            &[("smoke", "a", 2), ("other-p", "z", 9)],
            Ok(None),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 3, "suspect_keys": {"replay differs: z": 1, "other": 2}}}}"#,
            &[("smoke", "other", 1)],
            Ok(Some(
                "`campaign sweep-status` counts 2 suspects of smoke under `other` and `suspects.jsonl` lists 1",
            )),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 3, "suspect_keys": {"replay differs: z": 1, "other": 2}}}}"#,
            &[("smoke", "other", 2), ("smoke", "replay differs: z", 1)],
            Ok(None),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 1, "suspect_keys": {"replay differs": 1}}}}"#,
            &[],
            Ok(None),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 1, "suspect_keys": {"b": 1}}}}"#,
            &[("smoke", "a", 1)],
            Ok(Some(
                "`suspects.jsonl` lists 1 suspects of smoke under `a` and `campaign sweep-status` counts 0",
            )),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 3, "suspect_keys": {"a": 1, "other": 2}}}}"#,
            &[("smoke", "a", 2)],
            Ok(Some(
                "`suspects.jsonl` lists 2 suspects of smoke under `a` and `campaign sweep-status` counts 1",
            )),
        ),
        (
            r#"{"profiles": [1]}"#,
            &[],
            Err("the run failed: `campaign sweep-status` profiles is no object"),
        ),
        (
            NINES,
            &[],
            Err(
                "the run failed: the sum of the suspects by key has more digits than an integer holds",
            ),
        ),
    ];
    for (status, shown, expected) in rows {
        let status = if *status == NINES {
            let nines = "9".repeat(crate::json::MAX_INTEGER_DIGITS);
            format!(
                r#"{{"profiles": {{"smoke": {{"suspects": 1, "suspect_keys": {{"a": {nines}, "b": {nines}}}}}}}}}"#
            )
        } else {
            (*status).to_owned()
        };
        let Value::Object(status) = value(&status) else {
            panic!("an object");
        };
        let shown: BTreeMap<(Text, Text), usize> = shown
            .iter()
            .map(|&(profile, key, lines)| ((Text::from(profile), Text::from(key)), lines))
            .collect();
        let got = unlisted_replay(&status, &Text::from("smoke"), &shown);
        let got = got
            .map(|reason| reason.map(|reason| reason.to_string()))
            .map_err(|ending| ending.reason().to_string());
        let expected = expected
            .map(|reason| reason.map(str::to_owned))
            .map_err(str::to_owned);
        assert_eq!(got, expected, "{status:?} {shown:?}");
    }
}

/// A status with no object of profiles names none, whatever stands in its place.
#[test]
fn a_status_without_profiles_names_none() {
    use crate::plants::status::held_suspects;
    use crate::plants::verdict::Kind;

    for status in [r#"{}"#, r#"{"profiles": null}"#, r#"{"profiles": []}"#] {
        let Value::Object(status) = value(status) else {
            panic!("an object");
        };
        let refused = held_suspects(&status).expect_err("no profiles");
        assert_eq!(refused.kind(), Kind::Plain);
        assert_eq!(
            refused.reason().to_string(),
            "`campaign sweep-status` names no profiles"
        );
    }
}
