//! A mark's write called alone on a controller, and `run` over the system's own seam.

use std::cell::{Cell, RefCell};
use std::ffi::OsString;
use std::fs;
use std::rc::Rc;

use kestrike_tools::gameday::FILE_LIMIT;
use kestrike_tools::host_stop::{Delivered, Disk, Record, System};
use kestrike_tools::host_stop_controller::{Command, Context, Fault, Halt, entry};
use kestrike_tools::json::Value;

use super::steps::{Step, errno, syncs};
use super::{COPY, Case, Output, listing, set};
use crate::host_stop_support::{START, TARGET, json, met, tree, value};

fn request(time: f64) -> Value {
    value(&format!(
        r#"{{"identity": "arn:aws:sts::account:assumed-role/gameday-operator/gd2-run",
             "instance": "{TARGET}", "time": {time:?}}}"#
    ))
}

/// A mark's write syncs the file, links it, syncs the same file again and syncs the directory. A
/// sync after the link that fails removes the mark, which then counts as unwritten; a mark whose
/// removal also fails stands and counts as written.
#[test]
fn a_mark_is_synced_again_once_linked_and_a_failed_sync_removes_it() {
    let mut case = Case::new("synced-again");
    let seen: Rc<RefCell<Vec<String>>> = Rc::default();
    let failing: Rc<Cell<Option<usize>>> = Rc::default();
    let syncs_seen: Rc<Cell<usize>> = Rc::default();
    let keep: Rc<Cell<bool>> = Rc::default();
    let (log, nth, count, kept) = (
        Rc::clone(&seen),
        Rc::clone(&failing),
        Rc::clone(&syncs_seen),
        Rc::clone(&keep),
    );
    case.plant(Box::new(move |_, step| {
        log.borrow_mut().push(match step {
            Step::Fsync(fd) => format!("Fsync({fd})"),
            other => format!("{other:?}"),
        });
        if syncs(step) {
            count.set(count.get() + 1);
            if nth.get() == Some(count.get()) {
                return Some(errno(libc::EIO));
            }
        }
        (kept.get() && matches!(step, Step::Unlink(_))).then(|| errno(libc::EACCES))
    }));
    let evidence = case.evidence.clone();
    let written = case.controlled(|controller| {
        controller.set_injection(&evidence);
        controller
            .mark("stop", &request(START))
            .expect("the mark is written");
        let steps = seen.borrow().clone();
        let last: Vec<&str> = steps[steps.len() - 4..]
            .iter()
            .map(|step| step.split('(').next().unwrap_or_default())
            .collect();
        assert_eq!(
            last,
            ["Fsync", "Link", "Fsync", "FsyncDirectory"],
            "{steps:?}"
        );
        assert_eq!(
            steps[steps.len() - 4],
            steps[steps.len() - 2],
            "one file is synced twice"
        );
        assert!(steps[steps.len() - 4].starts_with("Fsync("), "{steps:?}");
        fs::remove_file(evidence.join("stop.json")).expect("the mark goes");

        syncs_seen.set(0);
        failing.set(Some(2));
        match controller.mark("stop", &request(START)) {
            Err(Halt::Fault(Fault::Unwritten(text))) => {
                assert!(
                    text.to_string().contains("so the mark is removed"),
                    "{text}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(listing(&evidence), [COPY]);
        assert_eq!(controller.written(), ["stop"]);

        syncs_seen.set(0);
        keep.set(true);
        match controller.mark("stop", &request(START)) {
            Err(Halt::Fault(Fault::Unwritten(text))) => {
                assert!(
                    text.to_string().contains("stands, but it cannot be synced"),
                    "{text}"
                );
            }
            other => panic!("{other:?}"),
        }
        controller.written().to_vec()
    });
    assert_eq!(listing(&case.evidence), [COPY, "stop.json"]);
    assert_eq!(
        written,
        ["stop", "stop"],
        "a mark that stands counts as written"
    );
}

/// A mark off the judge's layout is refused before any file step; a write that takes fewer bytes
/// than it is given still leaves the mark whole; a write that takes none fails the mark with the
/// system error `EIO` and leaves no entry; and a second mark of one name fails its link and keeps
/// the first mark's bytes.
#[test]
fn a_mark_is_written_once_and_leaves_no_other_file() {
    let mut case = Case::new("written-once");
    let evidence = case.evidence.clone();
    let (cap, stall) = (Rc::clone(&case.cap), Rc::clone(&case.stall));
    let written = case.controlled(|controller| {
        controller.set_injection(&evidence);
        let short = value(&format!(r#"{{"instance": "{TARGET}", "time": {START:?}}}"#));
        assert!(
            matches!(
                controller.mark("stop", &short),
                Err(Halt::Fault(Fault::Refusal(_)))
            ),
            "a mark off the layout is refused"
        );
        assert_eq!(
            (listing(&evidence), controller.written()),
            (vec![COPY.to_owned()], &[][..])
        );

        cap.set(Some(7));
        controller
            .mark("stop", &request(START))
            .expect("short writes complete");
        cap.set(None);
        let first = fs::read(evidence.join("stop.json")).expect("the mark reads");
        assert_eq!(value(&String::from_utf8_lossy(&first)), request(START));

        stall.set(true);
        let abort =
            value(r#"{"cause": "exception", "guardrail": null, "time": 104.0, "detail": "x"}"#);
        match controller.mark("abort", &abort) {
            Err(Halt::Fault(fault)) => {
                let text = fault.text().to_string();
                assert_eq!(
                    text,
                    "OSError: [Errno 5] a write of abort.json made no progress"
                );
            }
            other => panic!("{other:?}"),
        }
        stall.set(false);
        assert_eq!(listing(&evidence), [COPY, "stop.json"]);

        match controller.mark("stop", &request(START + 1.0)) {
            Err(Halt::Fault(fault)) => {
                assert_eq!(
                    fault.text().to_string(),
                    "FileExistsError: [Errno 17] File exists"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            fs::read(evidence.join("stop.json")).expect("the mark reads"),
            first
        );
        controller.written().to_vec()
    });
    assert_eq!(listing(&case.evidence), [COPY, "stop.json"]);
    assert_eq!(written, ["stop"]);
}

/// With the system's own seam and file steps, a `PATH` that names an empty directory gives the
/// caller's call no `aws` to start: the run exits 2 with `the caller is unknown` and writes nothing.
#[test]
fn a_run_with_no_aws_on_its_path_exits_2_and_writes_nothing() {
    let mut case = Case::new("no-aws");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
        - 10;
    case.repackage(|p| {
        set(
            p,
            &["baseline"],
            value(&format!(r#"{{"start": {}, "end": {now}}}"#, now - 300)),
        );
        set(
            p,
            &["run"],
            value(&format!(r#"{{"start": {now}, "end": {}}}"#, now + 30_000)),
        );
    });
    let lapse = super::plane::calendar(i64::try_from(now).expect("fits") + 200_000, 'T');
    set(
        &mut case.operator,
        &["approval", "not_after"],
        super::plane::string(&format!("{lapse}Z")),
    );
    let empty = case.scratch.0.join("empty");
    fs::create_dir(&empty).expect("the directory is made");
    fs::write(&case.catalog, json(&met())).expect("the catalog is written");
    let env = vec![(OsString::from("PATH"), empty.into_os_string())];
    let command = Command::Run {
        operator: case.write_operator(),
        package: case.package.clone(),
        evidence: case.evidence.clone().into_os_string(),
    };
    let delivered: &'static Delivered = Box::leak(Box::new(Delivered::new()));
    let mut record = Record::new(delivered);
    let output = Output::default();
    let (mut out, mut err) = (output.clone(), output.clone());
    let mut seam = System;
    let top = tree();
    let mut cx = Context {
        seam: &mut seam,
        files: &Disk,
        record: &mut record,
        env: &env,
        out: &mut out,
        err: &mut err,
        catalog: &case.catalog,
        top: &top,
        file_limit: FILE_LIMIT,
        mark_limit: FILE_LIMIT,
    };
    let code = entry(&command, &mut cx);
    let shown = String::from_utf8(output.0.borrow().clone()).expect("UTF-8 lines");
    assert_eq!(code, 2, "{shown}");
    assert_eq!(
        shown,
        "host-stop-controller: refused: the caller is unknown: sts get-caller-identity gave no \
         answer: no directory of PATH holds an executable aws; nothing written\n"
    );
    assert_eq!(listing(&case.evidence), [COPY]);
}

/// Each step asked for before the state it reads was set is a failure the controller names, and
/// none makes a call, a pause or a file.
#[test]
fn a_step_taken_out_of_its_order_is_a_failure_the_controller_names() {
    let mut case = Case::new("order");
    let monotonic = case.plane.borrow().t + super::plane::MONOTONIC;
    let sentences = case.controlled(|controller| {
        let mut sentences = Vec::new();
        let mut named = |ended: Result<(), Halt>| match ended {
            Err(Halt::Fault(Fault::Order(sentence))) => sentences.push(sentence),
            other => panic!("{other:?}"),
        };
        named(controller.ready().map(drop));
        named(controller.pause(monotonic + 1.0));
        named(controller.mark("stop", &request(START)));
        named(controller.await_stop(&request(START), 0.0).map(drop));
        sentences
    });
    assert_eq!(
        sentences,
        [
            "a stop request is checked before the run's preflight",
            "a poll pauses with no deadline set",
            "the mark stop has no injection directory to stand in",
            "the stop is awaited before the run's preflight",
        ]
    );
    assert_eq!(case.ops(), Vec::<String>::new());
    assert_eq!(case.plane.borrow().sleeps, 0);
    assert_eq!(listing(&case.evidence), [COPY]);
}
