use super::{
    ABSENT, ANNOUNCEMENT, BUILD_FAILURE, CRASH, INTERRUPTED, NOT_REPRODUCED, REJECTED, REPRODUCED,
    RESULTS, WATCHDOG, announcement, leg_directory, reported, verdict,
};
use crate::text::Text;

#[test]
fn the_seven_exit_codes_name_their_results() {
    let codes = [
        NOT_REPRODUCED,
        REPRODUCED,
        REJECTED,
        BUILD_FAILURE,
        CRASH,
        INTERRUPTED,
        WATCHDOG,
    ];
    assert_eq!(codes, [0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        RESULTS,
        [
            "not reproduced",
            "reproduced",
            "rejected input",
            "build failure",
            "crash",
            "interruption",
            "watchdog expiry"
        ]
    );
    assert_eq!((ABSENT, ANNOUNCEMENT), ("matched 0 listed", "artifact: "));
}

#[test]
fn reported_holds_for_a_reported_exit_whose_verdict_names_it() {
    let verdicts = [
        "",
        "not reproduced in 1 attempts",
        "reproduced: on attempt 1",
        "watchdog expiry: 30.0",
        "rejected input: x",
        "crash: x",
        "Not reproduced",
    ];
    for code in -2..8 {
        for (at, shown) in verdicts.iter().enumerate() {
            let expected = matches!((code, at), (0, 1) | (1, 2) | (6, 3));
            assert_eq!(
                reported(code, &Text::from(*shown)),
                expected,
                "{code} {shown:?}"
            );
        }
    }
}

#[test]
fn verdict_is_the_last_line_of_the_stripped_output() {
    let rows: [(&str, &[u8], &str); 10] = [
        ("no output", b"", ""),
        ("white space alone", b" \n\t\n", ""),
        (
            "one line",
            b"not reproduced in 1 attempts\n",
            "not reproduced in 1 attempts",
        ),
        (
            "the last of several lines",
            b"building\nreproduced: reproduced on attempt 1\n\n",
            "reproduced: reproduced on attempt 1",
        ),
        ("CR LF", b"a\r\nreproduced\r\n", "reproduced"),
        ("a lone CR", b"a\rcrash: x", "crash: x"),
        ("a group separator", b"a\x1cb", "b"),
        (
            "invalid UTF-8",
            b"crash: \xff\xfe\xc3",
            "crash: \u{fffd}\u{fffd}\u{fffd}",
        ),
        (
            "a truncated sequence",
            b"crash: \xe2\x82",
            "crash: \u{fffd}",
        ),
        (
            "an encoded surrogate",
            b"crash: \xed\xa0\x80",
            "crash: \u{fffd}\u{fffd}\u{fffd}",
        ),
    ];
    for (name, stdout, expected) in rows {
        assert_eq!(verdict(stdout), expected, "{name}");
    }
}

#[test]
fn announcement_is_the_text_after_the_last_artifact_line() {
    let rows: [(&str, &[u8], Option<&str>); 8] = [
        ("no announcement", b"error\n", None),
        (
            "one announcement",
            b"artifact: /r/local-1-1/local-1-1-1-base/artifact.json\n",
            Some("/r/local-1-1/local-1-1-1-base/artifact.json"),
        ),
        (
            "the last of two",
            b"artifact: /a/artifact.json\nnoise\nartifact: /b/artifact.json\n",
            Some("/b/artifact.json"),
        ),
        ("a bare announcement", b"artifact: \n", Some("")),
        ("a colon without a space", b"artifact:/a\n", None),
        (
            "CR LF",
            b"artifact: /a b/artifact.json\r\n",
            Some("/a b/artifact.json"),
        ),
        (
            "a line separator inside",
            "artifact: /a\u{2028}b\n".as_bytes(),
            Some("/a"),
        ),
        ("invalid UTF-8", b"artifact: /a\xff\n", Some("/a\u{fffd}")),
    ];
    for (name, stderr, expected) in rows {
        assert_eq!(announcement(stderr), expected.map(Text::from), "{name}");
    }
}

#[test]
fn a_leg_directory_is_named_by_run_attempt_and_leg() {
    let name = leg_directory(&Text::from("local-1-1"), &Text::from("2"), "head");
    assert_eq!(name, "local-1-1-2-head");
}
