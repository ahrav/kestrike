//! The refusals of the run's first step, through `run`: no call, nothing written.

use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command;

use super::{COPY, Case, listing};
use crate::host_stop_support::step_one::{Change, Evidence, ROWS, Reader};
use crate::host_stop_support::{gd2_mut, json, met, package, past_limit};

const CASE: &str =
    "host_stop_controller::step_one::each_refusal_of_step_1_sends_no_call_and_writes_nothing";
/// The variable that names the evidence directory a re-started test executable runs `run` from.
const FROM: &str = "HOST_STOP_CONTROLLER_FROM";

/// Applies the row's change to `case`.
fn plant(case: &mut Case, change: Change) {
    match change {
        Change::OperatorText(written) => case.operator_text = Some(written()),
        Change::Operator(change) => change(&mut case.operator),
        Change::Package(change) => case.repackage(change),
        Change::PackageBytes(bytes) => case.fill(bytes.as_bytes()),
        Change::Catalog(change) => {
            let mut catalog = met();
            change(gd2_mut(&mut catalog));
            fs::write(&case.catalog, json(&catalog)).expect("the catalog is written");
        }
        Change::PackagePastLimit => {
            let limit = past_limit();
            let mut data = package();
            data.extend(std::iter::repeat_n(
                b' ',
                usize::try_from(limit).expect("fits"),
            ));
            case.fill(&data);
            case.file_limit = limit;
        }
        Change::Evidence(evidence) => unreachable!("{evidence:?} is planted by its row"),
    }
}

/// `from_inside` runs in a process of its own: its working directory is the evidence directory, and
/// `run` names the evidence directory by an empty path.
fn from_inside(evidence: &std::path::Path) {
    let mut case = Case::new("empty-path");
    std::env::set_current_dir(&case.evidence).expect("the working directory changes");
    let code = case.run_with(std::ffi::OsString::new());
    let output = case.output();
    assert_eq!(code, 2, "{output}");
    assert_eq!(case.ops(), Vec::<String>::new(), "{output}");
    assert_eq!(listing(&case.evidence), [COPY], "{output}");
    assert_eq!(
        output,
        "host-stop-controller: refused: '' is no directory; nothing written\n"
    );
    fs::write(evidence.join("passed"), b"").expect("the marker is written");
}

/// Each row of the first step's table ends the run with exit 2 before any call and leaves the
/// evidence directory as it was. A row a reader decides prints `refused: ` and the reader's whole
/// sentence; every other row prints the part of its line the table names. An existing `injection`
/// stays as it is, and a missing evidence directory stays missing. The row that names the evidence
/// directory by an empty path runs in a process of its own, whose working directory is that
/// directory.
#[test]
fn each_refusal_of_step_1_sends_no_call_and_writes_nothing() {
    if let Some(place) = std::env::var_os(FROM) {
        from_inside(std::path::Path::new(&place));
        return;
    }
    assert_eq!(ROWS.len(), 48, "the self-test's rows");
    for row in ROWS {
        let mut case = Case::new("step-one");
        match row.change {
            Change::Evidence(Evidence::InjectionExists) => {
                fs::create_dir(case.evidence.join("injection")).expect("injection is made");
                assert_eq!(case.run(), 2, "{}", row.name);
                assert_eq!(case.ops(), Vec::<String>::new(), "{}", row.name);
                assert_eq!(listing(&case.evidence), ["injection", COPY]);
                assert!(case.output().contains(row.reason), "{}", case.output());
            }
            Change::Evidence(Evidence::Missing) => {
                fs::remove_dir_all(&case.evidence).expect("the evidence directory goes");
                assert_eq!(case.run(), 2, "{}", row.name);
                assert_eq!(case.ops(), Vec::<String>::new(), "{}", row.name);
                assert!(!case.evidence.exists(), "{}", row.name);
                assert!(case.output().contains(row.reason), "{}", case.output());
            }
            Change::Evidence(Evidence::Linked) => {
                let linked = case.scratch.0.join("linked");
                symlink(&case.evidence, &linked).expect("the link is made");
                case.evidence = linked;
                case.assert_refused(&[], row.reason);
            }
            Change::Evidence(Evidence::EmptyPath) => {
                let place = case.scratch.0.clone();
                let output = Command::new(std::env::current_exe().expect("the test executable"))
                    .args(["--exact", CASE, "--nocapture", "--test-threads", "1"])
                    .env_clear()
                    .env(FROM, &place)
                    .env("TMPDIR", std::env::temp_dir())
                    .output()
                    .expect("the test executable starts again");
                let shown = format!(
                    "{}\n{}{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(output.status.success(), "{shown}");
                assert!(place.join("passed").exists(), "{shown}");
            }
            change => {
                plant(&mut case, change);
                case.assert_refused(&[], row.reason);
                let output = case.output();
                match (row.reader, row.sentence) {
                    (Reader::Run, _) | (_, None) => {}
                    (_, Some(sentence)) => assert_eq!(
                        output,
                        format!("host-stop-controller: refused: {sentence}; nothing written\n"),
                        "{}",
                        row.name
                    ),
                }
                if row.name.contains("prerequisite") {
                    assert!(
                        output.contains(
                            "GD-2's prerequisites are not all met, so the catalog blocks its"
                        ),
                        "{output}"
                    );
                }
            }
        }
    }
}
