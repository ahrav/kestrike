//! A mark's write for each of the six marks: the order of its steps, each state a failed step leaves,
//! and the states a kill before and after the link leaves.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use kestrike_tools::host_stop::{Disk, Step, Unwritten, publish, sync_directory};

use super::{Fault, MARKER_LIMIT, Observed, PLACE, ROLE, Scratch, listing, passed, start_window};

const MARKS: [&str; 6] = [
    "roles",
    "stop",
    "stopped",
    "abort",
    "restoration",
    "collected",
];

fn file_name(mark: &str) -> String {
    format!("{mark}.json")
}

fn bytes_of(mark: &str) -> Vec<u8> {
    format!(
        "{{\n \"mark\": \"{mark}\",\n \"pad\": \"{}\"\n}}\n",
        "x".repeat(300)
    )
    .into_bytes()
}

fn umask() -> u32 {
    let status = fs::read_to_string("/proc/self/status").expect("the status reads");
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .expect("the status names the umask");
    u32::from_str_radix(line.trim(), 8).expect("an octal umask")
}

/// Each mark is written through the open directory: the unnamed file opens through
/// `/proc/self/fd/<directory>`, and the steps after the writes are the file's sync, the link, the file's
/// sync again and the directory's sync. The mark then holds its bytes with mode 0644 under the umask.
#[test]
fn each_mark_is_synced_linked_synced_again_and_its_directory_synced() {
    let scratch = Scratch::new("marks-order");
    for mark in MARKS {
        let directory = scratch.dir(mark);
        let files = Observed::default();
        publish(
            &files,
            &directory,
            OsStr::new(&file_name(mark)),
            &bytes_of(mark),
        )
        .expect("the mark is written");
        let seen = files.seen();
        let steps = files.steps();
        assert_eq!(steps[..2], ["open_directory", "open_unnamed"], "{mark}");
        assert_eq!(seen[0].path.as_deref(), Some(directory.as_path()));
        let written = steps.iter().filter(|step| **step == "write").count();
        assert!(written >= 1);
        let tail = &seen[2 + written..];
        let names: Vec<_> = tail.iter().map(|seen| seen.step).collect();
        assert_eq!(
            names,
            ["fsync", "link", "fsync", "fsync_directory"],
            "{mark}"
        );
        let (file, held) = (tail[1].fds[0], tail[1].fds[1]);
        assert_eq!(
            seen[1].path.as_deref(),
            Some(Path::new(&format!("/proc/self/fd/{held}"))),
            "the unnamed file opens in the held directory"
        );
        assert_eq!(
            (tail[0].fds[0], tail[2].fds[0]),
            (file, file),
            "the file is synced on both sides of its link"
        );
        assert_eq!(tail[3].fds[0], held, "the last sync is the directory's");
        assert!(seen[2..2 + written].iter().all(|seen| seen.fds == [file]));
        assert_eq!(listing(&directory), [file_name(mark)]);
        let path = directory.join(file_name(mark));
        assert_eq!(fs::read(&path).expect("the mark reads"), bytes_of(mark));
        let mode = fs::metadata(&path)
            .expect("the mark stands")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644 & !umask());
    }
}

/// A step that fails before the link leaves no entry, for each step and each mark: the directory's
/// open, the unnamed file's open, a write, a write that takes no byte and the first sync each end the
/// write with the step named, and the link's own failure leaves nothing named either.
#[test]
fn a_failure_before_the_link_leaves_no_entry() {
    let scratch = Scratch::new("marks-before");
    let cases = [
        ("open_directory", Step::OpenDirectory),
        ("open_unnamed", Step::OpenUnnamed),
        ("write", Step::Write),
        ("fsync", Step::Sync),
        ("link", Step::Link),
    ];
    for mark in MARKS {
        for (step, named) in cases {
            let directory = scratch.dir(&format!("{mark}-{step}"));
            let files = Observed::failing(&[Fault {
                step,
                nth: 1,
                errno: libc::EIO,
            }]);
            let failed = publish(
                &files,
                &directory,
                OsStr::new(&file_name(mark)),
                &bytes_of(mark),
            )
            .expect_err("the planted failure ends the write");
            match &failed {
                Unwritten::Failed { step, error } => {
                    assert_eq!((*step, error.raw_os_error()), (named, Some(libc::EIO)));
                }
                other => panic!("{mark} {step}: {other:?}"),
            }
            assert!(!failed.linked() && !failed.stands());
            let path = directory.join(file_name(mark));
            assert_eq!(failed.sentence(&path).to_string(), "Input/output error");
            assert_eq!(listing(&directory), Vec::<String>::new(), "{mark} {step}");
            assert_eq!(
                files.steps().last(),
                Some(&step),
                "the write ends at the failed step"
            );
        }
        let directory = scratch.dir(&format!("{mark}-stalled"));
        let files = Observed {
            stall: Some(1),
            ..Observed::default()
        };
        let stalled = publish(
            &files,
            &directory,
            OsStr::new(&file_name(mark)),
            &bytes_of(mark),
        );
        let Err(stalled) = stalled else {
            panic!("a write that takes no byte fails")
        };
        assert!(matches!(stalled, Unwritten::Stalled), "{stalled:?}");
        assert!(!stalled.linked() && !stalled.stands());
        let path = directory.join(file_name(mark));
        assert_eq!(
            stalled.sentence(&path).to_string(),
            format!("a write of {} made no progress", file_name(mark))
        );
        assert_eq!(
            files
                .steps()
                .iter()
                .filter(|step| **step == "write")
                .count(),
            1
        );
        assert_eq!(listing(&directory), Vec::<String>::new());
        for (case, fault, stall) in [
            (
                "failed",
                Some(Fault {
                    step: "write",
                    nth: 2,
                    errno: libc::ENOSPC,
                }),
                None,
            ),
            ("stalled", None, Some(2)),
        ] {
            let directory = scratch.dir(&format!("{mark}-partial-{case}"));
            let files = Observed {
                faults: fault.into_iter().collect(),
                write_cap: Some(7),
                stall,
                ..Observed::default()
            };
            let ended = publish(
                &files,
                &directory,
                OsStr::new(&file_name(mark)),
                &bytes_of(mark),
            )
            .expect_err("the second write ends the mark");
            match (case, &ended) {
                ("failed", Unwritten::Failed { step, error }) => {
                    assert_eq!(
                        (*step, error.raw_os_error()),
                        (Step::Write, Some(libc::ENOSPC))
                    );
                }
                ("stalled", Unwritten::Stalled) => {}
                (case, other) => panic!("{mark} {case}: {other:?}"),
            }
            assert!(!ended.linked() && !ended.stands());
            assert_eq!(
                files.steps(),
                ["open_directory", "open_unnamed", "write", "write"],
                "{mark} {case}"
            );
            assert_eq!(listing(&directory), Vec::<String>::new(), "{mark} {case}");
        }
    }
}

/// An entry at the mark's name, whether a file, a link or a directory, fails the link with `EEXIST`
/// and keeps its bytes, its target or its kind.
#[test]
fn an_entry_at_the_name_fails_the_link_and_keeps_its_bytes() {
    let scratch = Scratch::new("marks-exists");
    for mark in MARKS {
        let name = file_name(mark);
        for kind in ["file", "link", "dangling", "directory"] {
            let directory = scratch.dir(&format!("{mark}-{kind}"));
            let path = directory.join(&name);
            match kind {
                "file" => fs::write(&path, b"first").expect("the file is made"),
                "link" => {
                    fs::write(directory.join("target"), b"target").expect("the target is made");
                    symlink("target", &path).expect("the link is made");
                }
                "dangling" => symlink("missing", &path).expect("the link is made"),
                _ => fs::create_dir(&path).expect("the directory is made"),
            }
            let before = listing(&directory);
            let failed = publish(&Disk, &directory, OsStr::new(&name), &bytes_of(mark))
                .expect_err("an entry stands at the name");
            match failed {
                Unwritten::Failed {
                    step: Step::Link,
                    error,
                } => {
                    assert_eq!(error.raw_os_error(), Some(libc::EEXIST), "{mark} {kind}");
                }
                other => panic!("{mark} {kind}: {other:?}"),
            }
            assert_eq!(listing(&directory), before);
            match kind {
                "file" => assert_eq!(fs::read(&path).expect("reads"), b"first"),
                "link" | "dangling" => {
                    let target = fs::read_link(&path).expect("the link stands");
                    assert_eq!(
                        target,
                        Path::new(if kind == "link" { "target" } else { "missing" })
                    );
                }
                _ => assert!(fs::symlink_metadata(&path).expect("stands").is_dir()),
            }
        }
    }
}

/// A sync that fails after the link removes the mark and syncs the directory, and the result says
/// which of three states holds: removed, removed with the removal unsynced, or standing with its
/// removal failed. A standing mark keeps the whole of its bytes.
#[test]
fn a_failed_sync_after_the_link_removes_the_mark_and_names_what_holds() {
    let scratch = Scratch::new("marks-after");
    let file = |nth| Fault {
        step: "fsync",
        nth,
        errno: libc::EIO,
    };
    let directory_sync = |nth| Fault {
        step: "fsync_directory",
        nth,
        errno: libc::EIO,
    };
    let removal_sync = |nth| Fault {
        step: "fsync_directory",
        nth,
        errno: libc::ENOSPC,
    };
    let kept = Fault {
        step: "unlink",
        nth: 1,
        errno: libc::EACCES,
    };
    for mark in MARKS {
        let name = file_name(mark);
        let cases: [(&str, Vec<Fault>); 6] = [
            ("file sync", vec![file(2)]),
            ("directory sync", vec![directory_sync(1)]),
            ("removal unsynced", vec![file(2), removal_sync(1)]),
            (
                "directory removal unsynced",
                vec![directory_sync(1), removal_sync(2)],
            ),
            ("stands", vec![file(2), kept]),
            ("directory stands", vec![directory_sync(1), kept]),
        ];
        for (case, faults) in cases {
            let directory = scratch.dir(&format!("{mark}-{}", case.replace(' ', "-")));
            let files = Observed::failing(&faults);
            let failed = publish(&files, &directory, OsStr::new(&name), &bytes_of(mark))
                .expect_err("the planted sync fails");
            assert!(failed.linked(), "{mark} {case}");
            assert_eq!(failed.stands(), case.ends_with("stands"), "{mark} {case}");
            let path = directory.join(&name);
            let sentence = failed.sentence(&path).to_string();
            let shown = path.display();
            match (case, &failed) {
                ("file sync" | "directory sync", Unwritten::Removed { error }) => {
                    assert_eq!(error.raw_os_error(), Some(libc::EIO));
                    assert_eq!(
                        sentence,
                        format!(
                            "{shown} cannot be synced, so the mark is removed: Input/output error"
                        )
                    );
                    assert_eq!(listing(&directory), Vec::<String>::new());
                }
                (
                    "removal unsynced" | "directory removal unsynced",
                    Unwritten::RemovalUnsynced { error, removal },
                ) => {
                    assert_eq!(
                        (error.raw_os_error(), removal.raw_os_error()),
                        (Some(libc::EIO), Some(libc::ENOSPC))
                    );
                    assert_eq!(
                        sentence,
                        format!(
                            "{shown} cannot be synced (Input/output error), so it is removed; the \
                             removal is unsynced, so the mark may stand again after a crash"
                        )
                    );
                    assert_eq!(listing(&directory), Vec::<String>::new());
                }
                ("stands" | "directory stands", Unwritten::Stands { error, removal }) => {
                    assert_eq!(
                        (error.raw_os_error(), removal.raw_os_error()),
                        (Some(libc::EIO), Some(libc::EACCES))
                    );
                    assert!(failed.stands());
                    assert_eq!(
                        sentence,
                        format!(
                            "{shown} stands, but it cannot be synced (Input/output error) and cannot \
                             be removed, so it may not survive a crash"
                        )
                    );
                    assert_eq!(listing(&directory), std::slice::from_ref(&name));
                    assert_eq!(
                        fs::read(directory.join(&name)).expect("reads"),
                        bytes_of(mark)
                    );
                }
                (case, other) => panic!("{mark} {case}: {other:?}"),
            }
            let steps = files.steps();
            let first = faults[0];
            let at = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| **step == first.step)
                .nth(first.nth - 1)
                .map(|(at, _)| at)
                .expect("the failed sync is logged");
            let after: Vec<_> = steps[at + 1..].to_vec();
            let expected: &[&str] = if case.ends_with("stands") {
                &["unlink"]
            } else {
                &["unlink", "fsync_directory"]
            };
            assert_eq!(
                after, expected,
                "{mark} {case}: the removal follows the failed sync"
            );
            let seen = files.seen();
            let held = seen
                .iter()
                .find(|seen| seen.step == "link")
                .expect("linked")
                .fds[1];
            assert!(
                seen[at + 1..].iter().all(|seen| seen.fds == [held]),
                "{mark} {case}: the removal and its sync act on the held directory"
            );
        }
    }
}

/// Writes that each take at most seven bytes still write every byte once, in order. A write that
/// reports more bytes than it was given ends the loop, and the write goes on to its sync and link.
#[test]
fn short_writes_leave_the_mark_whole() {
    let scratch = Scratch::new("marks-short");
    for mark in MARKS {
        let directory = scratch.dir(mark);
        let files = Observed {
            write_cap: Some(7),
            ..Observed::default()
        };
        publish(
            &files,
            &directory,
            OsStr::new(&file_name(mark)),
            &bytes_of(mark),
        )
        .expect("the mark is written");
        let writes = files
            .steps()
            .iter()
            .filter(|step| **step == "write")
            .count();
        assert_eq!(writes, bytes_of(mark).len().div_ceil(7));
        assert_eq!(
            fs::read(directory.join(file_name(mark))).expect("reads"),
            bytes_of(mark)
        );
    }
    let directory = scratch.dir("interrupted");
    let files = Observed {
        faults: vec![Fault {
            step: "write",
            nth: 2,
            errno: libc::EINTR,
        }],
        write_cap: Some(7),
        ..Observed::default()
    };
    publish(
        &files,
        &directory,
        OsStr::new("stop.json"),
        &bytes_of("stop"),
    )
    .expect("an interrupted write runs again");
    let writes = files
        .steps()
        .iter()
        .filter(|step| **step == "write")
        .count();
    assert_eq!(writes, bytes_of("stop").len().div_ceil(7) + 1);
    assert_eq!(
        fs::read(directory.join("stop.json")).expect("reads"),
        bytes_of("stop")
    );
    let directory = scratch.dir("over");
    let files = Observed {
        overreport: true,
        ..Observed::default()
    };
    publish(
        &files,
        &directory,
        OsStr::new("stop.json"),
        &bytes_of("stop"),
    )
    .expect("the mark is written");
    assert_eq!(
        files
            .steps()
            .iter()
            .filter(|step| **step == "write")
            .count(),
        1
    );
    assert_eq!(listing(&directory), ["stop.json"]);
    assert_eq!(
        fs::read(directory.join("stop.json")).expect("reads"),
        bytes_of("stop")
    );
}

/// The mark's directory opens without following a link: a link to a directory fails the open with
/// `ENOTDIR`, and the directory it names stays empty.
#[test]
fn a_link_at_the_directory_fails_the_open() {
    let scratch = Scratch::new("marks-link");
    let real = scratch.dir("real");
    symlink(&real, scratch.0.join("link")).expect("the link is made");
    for mark in MARKS {
        let failed = publish(
            &Disk,
            &scratch.0.join("link"),
            OsStr::new(&file_name(mark)),
            &bytes_of(mark),
        );
        match failed {
            Err(Unwritten::Failed {
                step: Step::OpenDirectory,
                error,
            }) => assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR), "{mark}"),
            other => panic!("{mark}: {other:?}"),
        }
        assert_eq!(listing(&real), Vec::<String>::new());
    }
}

/// A name that is no single path component is refused before any step.
#[test]
fn a_name_other_than_one_component_takes_no_step() {
    let scratch = Scratch::new("marks-name");
    for name in ["", ".", "..", "a/b", "/abs", "nul\0"] {
        let files = Observed::default();
        let failed = publish(&files, &scratch.0, OsStr::new(name), b"{}\n");
        assert!(
            matches!(
                failed,
                Err(Unwritten::Failed {
                    step: Step::Name,
                    ..
                })
            ),
            "{name:?}"
        );
        assert!(files.steps().is_empty(), "{name:?}");
        let failed = failed.expect_err("refused");
        assert!(!failed.linked() && !failed.stands());
        assert_eq!(
            failed.sentence(&scratch.0.join("x")).to_string(),
            "a mark's name is one path component"
        );
    }
    assert_eq!(listing(&scratch.0), Vec::<String>::new());
}

/// The directory's sync opens the directory, following a link, and syncs it; a missing directory is
/// the open's error.
#[test]
fn a_directory_sync_opens_and_syncs_the_directory() {
    let scratch = Scratch::new("marks-sync");
    let directory = scratch.dir("real");
    symlink(&directory, scratch.0.join("link")).expect("the link is made");
    let files = Observed::default();
    sync_directory(&files, &scratch.0.join("link")).expect("a link to a directory syncs");
    assert_eq!(files.steps(), ["open_directory", "fsync_directory"]);
    let missing = sync_directory(&Disk, &scratch.0.join("missing")).expect_err("no directory");
    assert_eq!(missing.raw_os_error(), Some(libc::ENOENT));
}

const KILL_CASE: &str =
    "host_stop::marks::a_kill_before_the_link_leaves_no_entry_and_after_it_the_mark_stands";

/// `paused_write` writes the mark the window names in `PLACE/marks` and pauses at the step its cut
/// names, where the parent kills the process. With the file's second sync failed, the first directory
/// sync is the removal's.
fn paused_write(window: &str, place: &Path) {
    let (mark, cut) = window
        .split_once(':')
        .expect("a window names its mark and its cut");
    let sync_fails = Fault {
        step: "fsync",
        nth: 2,
        errno: libc::EIO,
    };
    let (step, nth, faults) = match cut {
        "link" => ("link", 1, vec![]),
        "file sync" => ("fsync", 2, vec![]),
        "directory sync" => ("fsync_directory", 1, vec![]),
        "removal" => ("unlink", 1, vec![sync_fails]),
        "removal sync" => ("fsync_directory", 1, vec![sync_fails]),
        other => panic!("no window {other}"),
    };
    let files = Observed {
        faults,
        pause: Some((step, nth, place.join("ready"))),
        ..Observed::default()
    };
    let written = publish(
        &files,
        &place.join("marks"),
        OsStr::new(&file_name(mark)),
        &bytes_of(mark),
    );
    panic!("the write returned {written:?} at a step that pauses");
}

/// If the writer exits or [`MARKER_LIMIT`] elapses before `paused` observes `ready`, `paused` attempts
/// to kill the writer, reaps it, and fails the case with its log.
fn paused(writer: &mut Child, ready: &Path, log: &Path) {
    let start = Instant::now();
    loop {
        if ready.exists() {
            return;
        }
        let ended = writer.try_wait().expect("the writer is waited on");
        let late = start.elapsed() >= MARKER_LIMIT;
        if ended.is_some() || late {
            let _ = writer.kill();
            let status = writer.wait().expect("the writer is reaped");
            let text = fs::read_to_string(log).unwrap_or_default();
            panic!("the writer ended {status} before its pause (late: {late}):\n{text}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// The link publishes the mark: SIGKILL at the `link` cut leaves the mark directory empty. At the
/// `file sync` and `directory sync` cuts, SIGKILL leaves the complete mark. In the removal after a
/// failed sync, SIGKILL at the `removal` cut leaves the complete mark and at the `removal sync` cut
/// leaves the directory empty.
#[test]
fn a_kill_before_the_link_leaves_no_entry_and_after_it_the_mark_stands() {
    if let (Some(window), Some(place)) = (std::env::var_os(ROLE), std::env::var_os(PLACE)) {
        paused_write(&window.to_string_lossy(), Path::new(&place));
        return;
    }
    let scratch = Scratch::new("marks-kill");
    for mark in MARKS {
        for (cut, stands) in [
            ("link", false),
            ("file sync", true),
            ("directory sync", true),
            ("removal", true),
            ("removal sync", false),
        ] {
            let place = scratch.dir(&format!("{mark}-{}", cut.replace(' ', "-")));
            let marks = place.join("marks");
            fs::create_dir(&marks).expect("the mark directory is made");
            let log = place.join("log");
            let mut writer = start_window(KILL_CASE, &format!("{mark}:{cut}"), &place, "")
                .stdout(Stdio::null())
                .stderr(File::create(&log).expect("the log is made"))
                .spawn()
                .expect("the writer starts");
            paused(&mut writer, &place.join("ready"), &log);
            writer.kill().expect("the writer is killed");
            let status = writer.wait().expect("the writer is reaped");
            assert_eq!(status.signal(), Some(libc::SIGKILL), "{mark} {cut}");
            if stands {
                assert_eq!(listing(&marks), [file_name(mark)], "{mark} {cut}");
                assert_eq!(
                    fs::read(marks.join(file_name(mark))).expect("reads"),
                    bytes_of(mark)
                );
            } else {
                assert_eq!(listing(&marks), Vec::<String>::new(), "{mark} {cut}");
            }
        }
    }
}

const MODE_CASE: &str = "host_stop::marks::a_mark_has_mode_0644_under_an_umask_of_0";

/// The child process isolates the process-wide `umask`; `000` preserves every requested permission
/// bit.
#[test]
fn a_mark_has_mode_0644_under_an_umask_of_0() {
    if let (Some(_), Some(place)) = (std::env::var_os(ROLE), std::env::var_os(PLACE)) {
        assert_eq!(umask(), 0);
        for mark in MARKS {
            let path = Path::new(&place).join(file_name(mark));
            publish(
                &Disk,
                Path::new(&place),
                OsStr::new(&file_name(mark)),
                &bytes_of(mark),
            )
            .expect("the mark is written");
            let mode = fs::metadata(&path).expect("stands").permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "{mark}");
        }
        return;
    }
    let scratch = Scratch::new("marks-mode");
    let output = start_window(MODE_CASE, "mode", &scratch.0, "umask 000;")
        .output()
        .expect("the window starts");
    passed("mode", &output);
    assert_eq!(
        listing(&scratch.0).len(),
        MARKS.len(),
        "the window wrote each mark"
    );
}

/// The sentence renders the invalid UTF-8 byte `0xff` as `\udcff` in both the full path and the
/// stalled write's name.
#[test]
fn a_sentence_keeps_a_path_byte_other_than_utf8() {
    let scratch = Scratch::new("marks-bytes");
    let directory = scratch.0.join(OsStr::from_bytes(b"evidence-\xff"));
    fs::create_dir(&directory).expect("the directory is made");
    let files = Observed::failing(&[Fault {
        step: "fsync",
        nth: 2,
        errno: libc::EIO,
    }]);
    let failed = publish(
        &files,
        &directory,
        OsStr::new("stop.json"),
        &bytes_of("stop"),
    )
    .expect_err("the planted sync fails");
    let sentence = failed.sentence(&directory.join("stop.json")).to_string();
    assert!(
        sentence.contains("evidence-\\udcff/stop.json cannot be synced"),
        "{sentence}"
    );
    assert!(!sentence.contains('\u{fffd}'), "{sentence}");
    let files = Observed {
        stall: Some(1),
        ..Observed::default()
    };
    let name = OsStr::from_bytes(b"stop-\xff.json");
    let stalled = publish(&files, &directory, name, &bytes_of("stop")).expect_err("stalls");
    assert_eq!(
        stalled.sentence(&directory.join(name)).to_string(),
        "a write of stop-\\udcff.json made no progress"
    );
}
