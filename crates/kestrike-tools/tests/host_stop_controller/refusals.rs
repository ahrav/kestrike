//! The refusals after the first step: the caller, the snapshot, the declared set's status, the
//! deadline before `injection/`, the roles mark's size, a signal that stands at the start, and an
//! evidence directory that cannot hold a mark.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;

use kestrike_tools::host_stop::{Interrupted, Signal};
use kestrike_tools::host_stop_controller::Halt;
use kestrike_tools::json::{Text, Value};

use super::plane::{Action, CALLER, STATUS, string};
use super::steps::{Step, errno};
use super::{COPY, Case, listing, set};
use crate::host_stop_support::{START, remove, value};

/// A row's name, its change of the case and the reason its refusal holds.
type Row<R> = (&'static str, fn(&mut Case), R);

fn number(text: &str) -> Value {
    value(text)
}

/// The caller check refuses another role, a session whose name the identity begins, a lost reply
/// and a reply whose `Arn` is no text, after the caller's call alone.
#[test]
fn a_wrong_or_unknown_caller_sends_no_stop_and_writes_nothing() {
    let identity = "arn:aws:sts::account:assumed-role/gameday-operator/gd2-run";
    let rows: [Row<String>; 4] = [
        (
            "another role",
            |case| {
                case.plane.borrow_mut().arn =
                    "arn:aws:sts::account:assumed-role/another-role/gd2-run".to_owned()
            },
            "the caller is arn:aws:sts::account:assumed-role/another".to_owned(),
        ),
        (
            "a session whose name the identity begins",
            |case| case.plane.borrow_mut().arn.push_str("-2"),
            format!("the caller is {identity}-2, not {identity}"),
        ),
        (
            "a lost reply",
            |case| case.plane.borrow_mut().script(CALLER, vec![Action::Lose]),
            "the caller is unknown".to_owned(),
        ),
        (
            "a reply whose Arn is no text",
            |case| {
                case.plane.borrow_mut().shape(
                    CALLER,
                    vec![Box::new(|mut reply| {
                        set(&mut reply, &["Arn"], Value::Null);
                        reply
                    })],
                );
            },
            "the caller is unknown: Arn is no str: None".to_owned(),
        ),
    ];
    for (name, change, reason) in rows {
        let mut case = Case::new("caller");
        change(&mut case);
        case.assert_refused(&[CALLER], &reason);
        assert!(case.output().contains(&reason), "{name}");
    }
}

type Rows = fn(&mut Vec<Value>);

/// Each malformed, stale or inconsistent snapshot is refused after the caller's call, with the part
/// of the refusal the row names; a fresh cut before the baseline window starts is refused too.
#[test]
fn a_stale_malformed_or_inconsistent_snapshot_is_refused_after_the_caller() {
    let changes: [(&str, &str, Rows, &str); 20] = [
        (
            "a stale shard record",
            "shards.jsonl",
            |rows| {
                for row in rows.iter_mut() {
                    set(row, &["time"], Value::Float(START - 61.0));
                }
            },
            "stale or ahead",
        ),
        (
            "a host report ahead of the clock",
            "hosts.jsonl",
            |rows| set(&mut rows[1], &["report", "time"], Value::Float(START + 1.0)),
            "stale or ahead",
        ),
        (
            "shard lines read at two times",
            "shards.jsonl",
            |rows| set(&mut rows[4], &["time"], number("101")),
            "not one cut",
        ),
        (
            "a missing shard",
            "shards.jsonl",
            |rows| {
                rows.pop();
            },
            "misses shards",
        ),
        (
            "a repeated shard",
            "shards.jsonl",
            |rows| {
                let first = rows[0].clone();
                rows.push(first);
            },
            "repeats shard",
        ),
        (
            "an owner outside the package",
            "shards.jsonl",
            |rows| set(&mut rows[3], &["owner"], string("h9")),
            "h9",
        ),
        (
            "an extra key",
            "shards.jsonl",
            |rows| set(&mut rows[0], &["note"], string("x")),
            "refused: ",
        ),
        (
            "a generation of 0",
            "shards.jsonl",
            |rows| set(&mut rows[4], &["generation"], number("0")),
            "generation is no generation of the layout: 0",
        ),
        (
            "a generation of 2^32",
            "shards.jsonl",
            |rows| set(&mut rows[4], &["generation"], number("4294967296")),
            "generation is no generation of the layout",
        ),
        (
            "attempts below 0",
            "shards.jsonl",
            |rows| set(&mut rows[4], &["attempts"], number("-1")),
            "attempts is no attempts of the layout: -1",
        ),
        (
            "attempts past the judge's ATTEMPTS_MAX",
            "shards.jsonl",
            |rows| set(&mut rows[4], &["attempts"], number("2147483647")),
            "attempts is no attempts of the layout",
        ),
        (
            "an extra key in a host line",
            "hosts.jsonl",
            |rows| set(&mut rows[1], &["note"], string("x")),
            "holds other keys",
        ),
        (
            "a health that is no boolean",
            "hosts.jsonl",
            |rows| set(&mut rows[1], &["report", "healthy"], string("yes")),
            "neither null nor",
        ),
        (
            "another target instance",
            "hosts.jsonl",
            |rows| set(&mut rows[0], &["instance"], string("i-h9")),
            "target instance",
        ),
        (
            "one instance for two hosts",
            "hosts.jsonl",
            |rows| set(&mut rows[2], &["instance"], string("i-h2")),
            "one instance twice",
        ),
        (
            "a host outside the package",
            "hosts.jsonl",
            |rows| set(&mut rows[2], &["host"], string("h9")),
            "no host of the",
        ),
        (
            "a repeated host line",
            "hosts.jsonl",
            |rows| {
                let mut again = rows[2].clone();
                set(&mut again, &["instance"], string("i-h4"));
                rows.push(again);
            },
            "repeats one",
        ),
        (
            "a host that is no text",
            "hosts.jsonl",
            |rows| set(&mut rows[2], &["host"], Value::Array(vec![string("h3")])),
            "no host of the",
        ),
        (
            "an owned shard with no witness key",
            "shards.jsonl",
            |rows| {
                set(&mut rows[3], &["owner"], string("h1"));
                set(&mut rows[3], &["standby"], string("h2"));
            },
            "no witness key",
        ),
        (
            "a witness key of a shard the target does not own",
            "shards.jsonl",
            |rows| set(&mut rows[2], &["owner"], string("h4")),
            "the target does not own",
        ),
    ];
    for (name, file, change, reason) in changes {
        let mut case = Case::new("snapshot");
        case.snapshot(file, change);
        case.assert_refused(&[CALLER], reason);
        assert!(case.output().contains(reason), "{name}");
    }
    let mut case = Case::new("snapshot-cut");
    case.repackage(|p| set(p, &["baseline", "start"], number("99")));
    case.snapshot("shards.jsonl", |rows| {
        for row in rows.iter_mut() {
            set(row, &["time"], number("98"));
        }
    });
    case.assert_refused(&[CALLER], "cut 98 lies before the baseline window");
}

fn mkfifo(path: &Path) {
    let name = CString::new(path.as_os_str().as_bytes()).expect("no NUL");
    // SAFETY: `name` is a NUL-terminated path that outlives the call.
    let status = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
    assert_eq!(status, 0, "{}", std::io::Error::last_os_error());
}

/// A snapshot file that is a named pipe is refused as no regular file without waiting for a
/// writer, and one that is a link is refused at its read.
#[test]
fn an_input_that_is_a_named_pipe_or_a_link_is_refused_without_waiting() {
    let mut case = Case::new("pipe");
    let hosts = case.scratch.0.join("snapshot/hosts.jsonl");
    fs::remove_file(&hosts).expect("the file goes");
    mkfifo(&hosts);
    case.assert_refused(&[CALLER], "hosts.jsonl is no regular file");

    let mut case = Case::new("link");
    let shards = case.scratch.0.join("snapshot/shards.jsonl");
    let elsewhere = case.scratch.0.join("shards-elsewhere.jsonl");
    fs::rename(&shards, &elsewhere).expect("the file moves");
    symlink(&elsewhere, &shards).expect("the link is made");
    case.assert_refused(&[CALLER], "shards.jsonl cannot be read");
}

/// A declared instance other than running, or a status read that fails, names another set or is
/// partial, is refused after the caller and the status read.
#[test]
fn a_declared_instance_not_running_or_an_unread_set_is_a_run_left_open() {
    let open = "are not running: a run is left open";
    let unread = "the declared instances' status is unknown";
    fn reshape(case: &mut Case, change: fn(&mut Vec<Value>)) {
        case.plane.borrow_mut().shape(
            STATUS,
            vec![Box::new(move |mut reply| {
                if let Value::Object(object) = &mut reply
                    && let Some(Value::Array(rows)) = object.get_mut("InstanceStatuses")
                {
                    change(rows);
                }
                reply
            })],
        );
    }
    fn state(case: &mut Case, id: &str, to: &str) {
        case.plane
            .borrow_mut()
            .instances
            .get_mut(id)
            .expect("declared")
            .state = to.to_owned();
    }
    let rows: [Row<&str>; 9] = [
        (
            "a stopped standby",
            |case| state(case, "i-h2", "stopped"),
            open,
        ),
        (
            "a standby that is stopping",
            |case| state(case, "i-h3", "stopping"),
            open,
        ),
        (
            "a stopped instance with no role",
            |case| state(case, "i-h4", "stopped"),
            open,
        ),
        (
            "a lost status reply",
            |case| case.plane.borrow_mut().script(STATUS, vec![Action::Lose]),
            unread,
        ),
        (
            "a status reply missing an instance",
            |case| {
                reshape(case, |rows| {
                    rows.pop();
                })
            },
            unread,
        ),
        (
            "a status reply naming an instance twice",
            |case| {
                reshape(case, |rows| {
                    let last = rows.last().cloned().expect("a row");
                    rows.push(last);
                })
            },
            unread,
        ),
        (
            "a status reply naming an instance outside the declared set",
            |case| {
                reshape(case, |rows| {
                    let mut other = rows.last().cloned().expect("a row");
                    set(&mut other, &["InstanceId"], string("i-h9"));
                    rows.push(other);
                })
            },
            unread,
        ),
        (
            "a status reply whose state is no text",
            |case| {
                reshape(case, |rows| {
                    set(&mut rows[0], &["InstanceState", "Name"], number("16"));
                })
            },
            unread,
        ),
        (
            "a partial status listing",
            |case| {
                case.plane.borrow_mut().shape(
                    STATUS,
                    vec![Box::new(|mut reply| {
                        set(&mut reply, &["NextToken"], string("t"));
                        reply
                    })],
                );
            },
            unread,
        ),
    ];
    for (name, change, reason) in rows {
        let mut case = Case::new("left-open");
        change(&mut case);
        case.assert_refused(&[CALLER, STATUS], reason);
        assert_eq!(
            case.log()[1].args,
            [
                "--include-all-instances",
                "--instance-ids",
                "i-h1",
                "i-h2",
                "i-h3",
                "i-h4"
            ],
            "the status read names the declared set"
        );
        assert!(case.output().contains(reason), "{name}");
    }
}

fn short_bounds(case: &mut Case) {
    set(
        &mut case.operator,
        &["effect_timeout_seconds"],
        number("10"),
    );
    set(&mut case.operator, &["observe_seconds"], number("10"));
    set(&mut case.operator, &["deadline_seconds"], number("30"));
}

/// Each call before `injection/` is cut at the time the deadline leaves, and a deadline passed in a
/// call, after it, or once the roles mark is built is a refusal.
#[test]
fn a_deadline_passed_before_injection_is_a_refusal() {
    let mut case = Case::new("deadline-caller");
    short_bounds(&mut case);
    case.plane
        .borrow_mut()
        .script(CALLER, vec![Action::Delay(40.0)]);
    case.assert_refused(
        &[CALLER],
        "the deadline of 30 s passed before injection/ was made",
    );
    assert_eq!(case.log()[0].timeout, 30.0);

    let mut case = Case::new("deadline-status");
    short_bounds(&mut case);
    case.plane
        .borrow_mut()
        .script(CALLER, vec![Action::Delay(25.0)]);
    case.plane
        .borrow_mut()
        .script(STATUS, vec![Action::Delay(10.0)]);
    case.assert_refused(&[CALLER, STATUS], "the deadline of 30 s passed");
    let log = case.log();
    assert!(
        (log[1].timeout - (30.0 - 25.2)).abs() < 1e-6,
        "{:?}",
        log[1]
    );
    assert!((log[1].start - (START + 25.2)).abs() < 1e-9, "{:?}", log[1]);
    for logged in &log {
        let left = logged.left.expect("the deadline is set");
        assert!(logged.timeout <= left.min(60.0) + 1e-9, "{logged:?}");
    }

    let mut case = Case::new("deadline-roles");
    short_bounds(&mut case);
    case.plane.borrow_mut().after = Some(Box::new(|state, op| {
        if op == STATUS {
            state.t += 31.0;
        }
    }));
    case.assert_refused(
        &[CALLER, STATUS],
        "the deadline of 30 s passed before injection/",
    );
}

/// A roles mark whose bytes pass the mark size limit, from a snapshot under that limit, is refused
/// before `injection/` is made.
#[test]
fn a_roles_mark_past_the_judges_file_size_is_refused_before_injection() {
    let mut case = Case::new("roles-size");
    case.mark_limit = 4000;
    let path = case.scratch.0.join("snapshot/shards.jsonl");
    let text = fs::read_to_string(&path).expect("the snapshot reads");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    lines[4] = lines[4].replace("\"vol-s5\"", &format!("\"{}\"", "\u{e9}".repeat(600)));
    fs::write(
        &path,
        lines
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>(),
    )
    .expect("the snapshot is written");
    assert!(fs::metadata(&path).expect("stands").len() < 4000);
    case.assert_refused(&[CALLER, STATUS], "more than the judge reads");
}

/// A signal that stands before the run arms raises at its first read, before any call.
#[test]
fn a_pending_signal_ends_the_run_before_any_call() {
    let mut case = Case::new("pending");
    case.delivered.deliver(Signal::Terminate);
    let (package, evidence) = (case.package.clone(), case.evidence.clone());
    let ended = case.controlled(|controller| controller.run(&package, evidence.as_os_str()));
    assert!(
        matches!(
            ended,
            Err(Halt::Interrupted(Interrupted(Signal::Terminate)))
        ),
        "{ended:?}"
    );
    assert_eq!(case.ops(), Vec::<String>::new());
    assert_eq!(listing(&case.evidence), [COPY]);
}

/// An evidence directory that takes no unnamed file, or whose unnamed file's `/proc/self/fd` path
/// does not resolve, is refused before any call.
#[test]
fn an_evidence_directory_with_no_unnamed_file_or_no_link_to_one_is_refused() {
    let mut case = Case::new("unnamed");
    let evidence = case.evidence.clone();
    case.fail_once(
        libc::EOPNOTSUPP,
        move |step| matches!(step, Step::OpenUnnamed(path) if *path == evidence),
    );
    case.assert_refused(&[], "takes no unnamed file");

    let mut case = Case::new("unresolved");
    case.plant(Box::new(|_, step| {
        matches!(step, Step::Exists(path) if path.starts_with("/proc/self/fd/"))
            .then(|| errno(libc::ENOENT))
    }));
    case.assert_refused(&[], "does not resolve");
    let _ = (remove, Text::new());
}
