use std::cell::Cell;
use std::os::unix::ffi::OsStringExt;
use std::rc::Rc;

use kestrike_tools::host_stop::DETAIL_MAX;
use kestrike_tools::json::{Text, Value};

use super::plane::{Action, STATUS};
use super::steps::{Step, errno, links, syncs};
use super::{COPY, Case, guardrails, member, set, tail};

const ALL: [&str; 4] = ["roles", "stop", "stopped", "abort"];

fn guardrail_after_stop(case: &Case) {
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-5", "ALARM");
            Action::Answer
        })),
        false,
    );
}

fn unsynced(case: &Case, name: &'static str) {
    let mut linked = false;
    case.plant(Box::new(move |_, step| {
        if links(step, name) {
            linked = true;
        } else if linked && syncs(step) {
            linked = false;
            return Some(errno(libc::EIO));
        }
        None
    }));
}

#[test]
fn an_abort_mark_that_stands_unsynced_is_followed_by_the_stopped_mark() {
    let mut case = Case::new("abort-stands");
    guardrail_after_stop(&case);
    unsynced(&case, "abort.json");
    case.fail_once(
        libc::EACCES,
        |step| matches!(step, Step::Unlink(name) if *name == "abort.json"),
    );
    let found = case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    assert_eq!(member(&found["stopped"], "request"), &found["stop"]);
    let stderr = case.stderr();
    assert!(
        stderr.starts_with("host-stop-controller: abort.json stands with its durability unknown: "),
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
}

#[test]
fn a_panic_at_the_abort_marks_link_leaves_it_unwritten_and_the_steps_printed() {
    let mut case = Case::new("abort-link-panic");
    guardrail_after_stop(&case);
    case.plant(Box::new(|_, step| {
        assert!(!links(step, "abort.json"), "a planted link fault");
        None
    }));
    let code = case.run();
    assert_eq!(code, 1, "{}", case.output());
    let names: Vec<String> = case.marks().into_keys().collect();
    assert_eq!(names, ["roles", "stop"]);
    let stderr = case.stderr();
    assert!(
        stderr.starts_with(
            "host-stop-controller: abort.json is unwritten: panic: a planted link fault"
        ),
        "{stderr}"
    );
    let stdout = case.stdout();
    let last: Vec<&str> = stdout.lines().rev().take(2).collect();
    assert!(
        last[1].starts_with("host-stop-controller: the target reads {"),
        "{stdout}"
    );
    assert!(
        last[0].starts_with("GD-2's restoration steps: "),
        "{stdout}"
    );
    assert_eq!(case.after_fault(), [STATUS]);
}

#[test]
fn a_panic_in_the_abort_status_read_or_its_line_says_the_state_is_unknown() {
    let mut case = Case::new("status-panic");
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-5", "ALARM");
            let panicking = Action::Hook(Box::new(|_| panic!("a planted status fault")));
            state.script(STATUS, vec![panicking]);
            Action::Answer
        })),
        false,
    );
    case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    let line =
        "host-stop-controller: the target's state is unknown: panic: a planted status fault\n";
    assert!(case.stdout().contains(line), "{}", case.stdout());

    let mut case = Case::new("status-line-panic");
    guardrail_after_stop(&case);
    let panicked = Rc::new(Cell::new(false));
    let once = Rc::clone(&panicked);
    case.writes = Some(Rc::new(move |bytes: &[u8]| {
        if bytes.starts_with(b"host-stop-controller: the target reads {") && !once.replace(true) {
            panic!("a planted stream fault");
        }
        None
    }));
    case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    assert!(panicked.get());
    let line =
        "host-stop-controller: the target's state is unknown: panic: a planted stream fault\n";
    assert!(case.stdout().contains(line), "{}", case.stdout());
    assert_eq!(case.after_fault(), [STATUS]);
}

/// The evidence path holds the byte 0xff, which a text keeps as the lone surrogate U+DCFF, and the
/// final `stopped.json` is removed after a failed sync, so the abort's detail names the path. The
/// abort mark is written with the byte as the six characters `\udcff`, and the abort path's own
/// write of `stopped.json`, whose sync fails again, is named unwritten on standard error.
#[test]
fn a_final_stopped_mark_removed_under_a_path_with_no_utf8_form_is_named_in_the_abort_mark() {
    let mut case = Case::new("bytes-path");
    let mut name = case.scratch.0.clone().into_os_string().into_vec();
    name.extend_from_slice(b"/ev\xff");
    let evidence = std::path::PathBuf::from(std::ffi::OsString::from_vec(name));
    std::fs::create_dir(&evidence).expect("the evidence directory is made");
    std::fs::copy(case.evidence.join(COPY), evidence.join(COPY)).expect("the copy is made");
    case.evidence.clone_from(&evidence);
    case.plane.borrow_mut().evidence = evidence;
    unsynced(&case, "stopped.json");
    let found = case.assert_aborted(
        "exception",
        &["roles", "stop", "abort"],
        None,
        Some("ev\\udcff/injection/stopped.json cannot be synced, so the mark is removed"),
    );
    assert!(detail_of(&found).contains("ev\\udcff/injection/stopped.json"));
    let stderr = case.stderr();
    assert!(
        stderr.starts_with("host-stop-controller: stopped.json is unwritten: Unwritten: "),
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
}

/// The detail of the abort mark among `found`, a text with a UTF-8 form, so one that holds no
/// surrogate.
fn detail_of(found: &std::collections::BTreeMap<String, Value>) -> String {
    match member(&found["abort"], "detail") {
        Value::String(detail) => detail
            .to_str()
            .expect("the detail holds no surrogate")
            .to_owned(),
        other => panic!("{other:?} is the abort's detail"),
    }
}

/// Sets the `StateValue` of the fifth guardrail's alarm to `state` at the first alarm read after
/// the stop is shown.
fn state_after_stop(case: &Case, state: Text) {
    case.faulted(
        Action::Hook(Box::new(move |plane| {
            plane.row("gd2-guardrail-5", "StateValue", Some(Value::String(state)));
            Action::Answer
        })),
        false,
    );
}

/// The words of an abort's detail ahead of the state an alarm reads once the stop is shown.
const READS: &str = "the stop request was sent and answered; alarm gd2-guardrail-5 reads ";

/// The alarm reply's `StateValue` holds U+D800 once the stop is shown. The abort mark is written
/// with the surrogate as the six characters `\ud800` in its detail, which JSON writes with the
/// backslash doubled, `stopped.json` follows it, standard error is empty, and the abort's line on
/// standard output holds the mark's detail.
#[test]
fn a_lone_surrogate_in_an_alarm_reply_is_written_as_its_escape_in_the_abort_mark() {
    let mut case = Case::new("surrogate-reply");
    let surrogate = Text::from_code_points([0xd800]).expect("a text holds a lone surrogate");
    state_after_stop(&case, surrogate);
    let found = case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    assert_eq!(detail_of(&found), format!("{READS}\\ud800{}", tail()));
    assert_eq!(member(&found["stopped"], "request"), &found["stop"]);
    assert_eq!(case.stderr(), "");
    let bytes = std::fs::read(case.evidence.join("injection/abort.json")).expect("the mark reads");
    let written = String::from_utf8(bytes).expect("the mark's bytes are UTF-8");
    assert!(written.contains("reads \\\\ud800; "), "{written}");
    assert_eq!(case.after_fault(), [STATUS]);
}

/// A surrogate is written as its six characters before the detail is cut at [`DETAIL_MAX`]
/// characters ahead of the steps' digest. One at the detail's start moves five characters past the
/// cut; one at the last kept place leaves the escape's backslash there; and one at the first place
/// past the cut is dropped with the rest, so that mark holds the bytes of the mark for the same
/// state with a letter in the surrogate's place.
#[test]
fn a_surrogate_is_escaped_before_the_details_cut_and_one_past_the_cut_changes_no_byte() {
    let kept = DETAIL_MAX - tail().chars().count();
    let room = kept - READS.chars().count();
    let state = |before: usize, code: u32| {
        let codes = std::iter::repeat_n(u32::from(b'a'), before)
            .chain([code])
            .chain(std::iter::repeat_n(u32::from(b'b'), room));
        Text::from_code_points(codes).expect("each code point is one of a text")
    };
    let written = |state: Text| {
        let mut case = Case::new("surrogate-cut");
        state_after_stop(&case, state);
        let found = case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
        assert_eq!(case.stderr(), "");
        let bytes = std::fs::read(case.evidence.join("injection/abort.json"));
        (detail_of(&found), bytes.expect("the mark reads"))
    };
    let whole = |shown: String| {
        let cut: String = format!("{READS}{shown}").chars().take(kept).collect();
        format!("{cut}{}", tail())
    };
    let (detail, _) = written(state(0, 0xdfff));
    assert_eq!(detail, whole(format!("\\udfff{}", "b".repeat(room))));
    assert_eq!(detail.chars().count(), DETAIL_MAX);
    let (detail, _) = written(state(room - 1, 0xd800));
    assert_eq!(detail, whole(format!("{}\\", "a".repeat(room - 1))));
    assert_eq!(detail.chars().count(), DETAIL_MAX);
    let (detail, bytes) = written(state(room, 0xd800));
    assert_eq!(detail, whole("a".repeat(room)));
    let (plain, plain_bytes) = written(state(room, u32::from(b'x')));
    assert_eq!((detail, bytes), (plain, plain_bytes));

    let codes = std::iter::repeat_n(u32::from(b'a'), room - 1).chain([0x1f600, 0xe9]);
    let (detail, bytes) = written(Text::from_code_points(codes).expect("code points of a text"));
    assert_eq!(detail, whole(format!("{}\u{1f600}", "a".repeat(room - 1))));
    assert_eq!(detail.chars().count(), DETAIL_MAX);
    let kept_whole = format!("a\\ud83d\\ude00{}\",\n", tail());
    assert!(String::from_utf8_lossy(&bytes).contains(&kept_whole));

    let codes = (0..3 * DETAIL_MAX).flat_map(|_| [0xdc80, u32::from(b'a'), u32::from(b'b')]);
    let (detail, _) = written(Text::from_code_points(codes).expect("code points of a text"));
    assert_eq!(detail, whole("\\udc80ab".repeat(3 * DETAIL_MAX)));
    assert_eq!(detail.chars().count(), DETAIL_MAX);
}

/// The mark's `detail` line for the alarm state `state`, as the file holds it.
fn detail_line(state: Text) -> String {
    let mut case = Case::new("surrogate-bytes");
    state_after_stop(&case, state);
    case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    assert_eq!(case.stderr(), "");
    let bytes = std::fs::read(case.evidence.join("injection/abort.json")).expect("the mark reads");
    let text = String::from_utf8(bytes).expect("the mark's bytes are UTF-8");
    let line = text.lines().find(|line| line.starts_with(" \"detail\": "));
    line.expect("the mark holds a detail").to_owned()
}

/// A state with no surrogate keeps each character: a backslash that starts the letters of an
/// escape, a tab, a scalar of the basic plane and one past it reach the mark as JSON writes them.
/// Each of two lone surrogates in one state is written as its own six characters.
#[test]
fn the_abort_detail_keeps_a_text_with_no_surrogate_and_escapes_each_surrogate_of_one() {
    let plain = Text::from("q\\ud800w\t\u{e9}\u{1f600}z");
    assert_eq!(
        detail_line(plain),
        format!(
            " \"detail\": \"{READS}q\\\\ud800w\\t\\u00e9\\ud83d\\ude00z{}\",",
            tail()
        )
    );
    let codes = [0xd800, u32::from(b'x'), 0xdfff];
    let twice = Text::from_code_points(codes).expect("a text holds lone surrogates");
    assert_eq!(
        detail_line(twice),
        format!(" \"detail\": \"{READS}\\\\ud800x\\\\udfff{}\",", tail())
    );
}

#[test]
fn a_stop_mark_past_the_mark_size_limit_is_refused_before_any_stop_request() {
    let mut case = Case::new("stop-too-large");
    let identity = format!(
        "arn:aws:sts::000000000000:assumed-role/{}",
        "r".repeat(6000)
    );
    set(
        &mut case.operator,
        &["identity"],
        Value::String(Text::from(identity.as_str())),
    );
    case.plane.borrow_mut().arn = identity;
    case.mark_limit = 5000;
    case.assert_aborted(
        "exception",
        &["roles", "abort"],
        None,
        Some("no stop request was sent; Refusal: injection/stop.json would hold "),
    );
    assert!(case.stops().is_empty(), "{:?}", case.ops());
}

#[test]
fn a_stopped_mark_that_fails_in_the_abort_path_is_named_unwritten() {
    let mut case = Case::new("abort-path-stopped");
    guardrail_after_stop(&case);
    case.fail_once(libc::ENOSPC, |step| links(step, "stopped.json"));
    case.assert_aborted(
        "guardrail",
        &["roles", "stop", "abort"],
        Some(&guardrails()[4]),
        None,
    );
    let stderr = case.stderr();
    assert!(
        stderr.starts_with("host-stop-controller: stopped.json is unwritten: OSError: [Errno 28]"),
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert_eq!(case.after_fault(), [STATUS]);
}
