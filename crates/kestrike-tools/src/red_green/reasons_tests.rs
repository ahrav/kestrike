use std::path::PathBuf;

use super::{NO_EVIDENCE, base_reason, head_reason, tree_reason};
use crate::red_green::evidence::{Evidence, Readings};
use crate::red_green::options::{DEFAULT_WATCHDOG, Options};
use crate::red_green::record::Leg;
use crate::text::Text;

const TEST: &str = "storage::device::table_tests::a_poll_reports_each_completion_once";
const EXPECT: &str = "a poll counts that completion as delivered";

fn read(outputs: &[(&'static str, &str)]) -> Evidence {
    Evidence::Read(Readings {
        artifact: PathBuf::from("/r/a/artifact.json"),
        data: b"{}\n".to_vec(),
        outputs: outputs
            .iter()
            .map(|(stream, data)| (*stream, data.as_bytes().to_vec()))
            .collect(),
    })
}

pub(crate) fn options(test: &str, expect: &str) -> Options {
    Options {
        package: Text::from("p"),
        target: Text::from("lib"),
        test: Text::from(test),
        expect: Text::from(expect),
        carry: vec![Text::from("t.rs")],
        base: None,
        head: Text::from("HEAD"),
        watchdog: DEFAULT_WATCHDOG,
        artifacts: None,
        cargo: Text::from("cargo"),
        release: false,
    }
}

pub(crate) fn leg(exit: i32, verdict: &str, evidence: Evidence) -> Leg {
    Leg {
        exit,
        verdict: Text::from(verdict),
        seconds: 1.0,
        evidence,
        expect_streams: None,
    }
}

fn both() -> Evidence {
    read(&[("stdout", EXPECT), ("stderr", "")])
}

#[test]
fn base_reason_names_each_outcome_of_the_base_leg() {
    let red = "reproduced: on attempt 1";
    let failed = format!("the base leg failed but {NO_EVIDENCE}: {red}");
    let incomplete = |code: i32, verdict: &str| {
        format!("the runner did not complete the base leg: exit {code}, verdict {verdict}")
    };
    #[rustfmt::skip]
    type Row<'a> = (&'a str, i32, &'a str, Evidence, Option<String>, Option<Vec<&'a str>>);
    let rows: Vec<Row> = vec![
        ("a red base", 1, red, both(), None, Some(vec!["stdout"])),
        ("a red base on standard error", 1, red, read(&[("stdout", ""), ("stderr", EXPECT)]), None,
         Some(vec!["stderr"])),
        ("a failure without the text", 1, red, read(&[("stdout", "x"), ("stderr", "")]),
         Some(format!("the test failed on the base without the expected text: {red}; the search skips framing and \
                       backtrace lines")), Some(vec![])),
        ("a failure without evidence", 1, red, Evidence::Absent, Some(failed.clone()), None),
        ("a failure after a failed read", 1, red, Evidence::Unreadable(Text::from("x")), Some(failed.clone()), None),
        ("a failure with one stream", 1, red, read(&[("stdout", EXPECT)]), Some(failed), None),
        ("an unreported failure", 1, "Traceback", both(), Some(incomplete(1, "'Traceback'")), None),
        ("a pass", 0, "not reproduced in 1 attempts", both(),
         Some("the test passes on the base: not reproduced in 1 attempts".to_owned()), None),
        ("an unreported pass", 0, "", both(), Some(incomplete(0, "''")), None),
        ("a build failure", 3, "build failure: cargo exited 101", Evidence::Absent,
         Some("the base is red for the wrong reason, a build failure: build failure: cargo exited 101".to_owned()),
         None),
        ("a build failure without a verdict", 3, "", Evidence::Absent,
         Some("the base is red for the wrong reason, a build failure: ".to_owned()), None),
        ("an absent test", 2, "rejected input: 'x' matched 0 listed and 0 ignored tests", Evidence::Absent,
         Some("the test is absent on the base: rejected input: 'x' matched 0 listed and 0 ignored tests".to_owned()),
         None),
        ("another rejection", 2, "rejected input: cargo metadata exited 1", Evidence::Absent,
         Some(incomplete(2, "'rejected input: cargo metadata exited 1'")), None),
        ("a crash", 4, "crash: signal 11", Evidence::Absent,
         Some("the test crashed on the base: crash: signal 11".to_owned()), None),
        ("an interruption", 5, "interruption: interrupted by signal 15", Evidence::Absent,
         Some(incomplete(5, "'interruption: interrupted by signal 15'")), None),
        ("a hang", 6, "watchdog expiry: 30.0", Evidence::Absent,
         Some("the test hung on the base: watchdog expiry: 30.0".to_owned()), None),
        ("an unreported hang", 6, "crash", Evidence::Absent, Some(incomplete(6, "'crash'")), None),
        ("a signal death", -9, "", Evidence::Absent, Some(incomplete(-9, "''")), None),
        ("an exit outside the codes", 7, "x\u{2028}'y", Evidence::Absent,
         Some(incomplete(7, "\"x\\u2028'y\"")), None),
    ];
    for (name, code, verdict, evidence, reason, streams) in rows {
        let mut judged = leg(code, verdict, evidence);
        let found = base_reason(&mut judged, &options(TEST, EXPECT));
        assert_eq!(found, reason.map(Text::from), "{name}");
        assert_eq!(judged.expect_streams, streams, "{name}");
    }
}

#[test]
fn head_reason_names_each_outcome_of_the_head_leg() {
    let green = "not reproduced in 1 attempts";
    let passed = format!("the head leg passed but {NO_EVIDENCE}: {green}");
    #[rustfmt::skip]
    let rows: Vec<(&str, i32, &str, Evidence, Option<String>)> = vec![
        ("a green head", 0, green, both(), None),
        ("a pass without evidence", 0, green, Evidence::Absent, Some(passed.clone())),
        ("a pass with one stream", 0, green, read(&[("stderr", "")]), Some(passed)),
        ("a failure", 1, "reproduced: on attempt 1", both(),
         Some("the test fails on the head: reproduced: on attempt 1".to_owned())),
        ("an unreported failure", 1, "", both(), Some("the head leg did not pass: exit 1, verdict ''".to_owned())),
        ("an unreported pass", 0, "", both(), Some("the head leg did not pass: exit 0, verdict ''".to_owned())),
        ("a hang", 6, "watchdog expiry: 30.0", Evidence::Absent,
         Some("the head leg did not pass: exit 6, verdict 'watchdog expiry: 30.0'".to_owned())),
        ("a signal death", -15, "", Evidence::Absent,
         Some("the head leg did not pass: exit -15, verdict ''".to_owned())),
    ];
    for (name, code, verdict, evidence, reason) in rows {
        assert_eq!(
            head_reason(&leg(code, verdict, evidence)),
            reason.map(Text::from),
            "{name}"
        );
    }
}

#[test]
fn tree_reason_quotes_the_leg_and_the_path() {
    let tail = "; Git configuration such as a filter or a line-ending conversion changes what a checkout writes";
    let rows = [
        (
            "base",
            Text::from("a.txt"),
            format!("the base leg's tree differs from its commit at 'a.txt'{tail}"),
        ),
        (
            "head",
            Text::from_os(std::os::unix::ffi::OsStrExt::from_bytes(b"n\xff")),
            format!("the head leg's tree differs from its commit at 'n\\udcff'{tail}"),
        ),
    ];
    for (leg, path, expected) in rows {
        assert_eq!(tree_reason(leg, &path), Text::from(expected));
    }
}
