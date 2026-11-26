//! Session output and session replay tests: the end line keeps its text
//! values, and each replay divergence keeps the window, record, tag,
//! virtual time and candidate the worker printed, with no value the line
//! does not name.

use super::fixture::{SESSION, edited, twice, without};
use super::{Candidate, Divergence, End, Error, Outcome, Session, SessionReplay, Terminal};

const CHAIN: &str = "e1bc09f574b9f7060a1ccf70b20f88b4afcec88c2e9f678edfe55893c5ca870b";

#[test]
fn a_session_parses_its_windows_chain_and_end() {
    let session = Session::parse(SESSION).expect("the fixture parses");
    assert_eq!(
        (session.windows, session.chain.to_string()),
        (3, CHAIN.to_owned())
    );
    let end = session.end;
    assert_eq!(end.stop, "goal");
    assert_eq!(
        end.terminal,
        Terminal::Complete {
            outcome: Outcome::Pass,
            fired: 3,
            required: 3
        }
    );
    assert!(end.counts);
    assert_eq!(
        (
            end.turns,
            end.virtual_us,
            end.skipped_us,
            end.rested_us,
            end.apply_ms
        ),
        (1113, 5700, 5100, 300, 4)
    );
    assert_eq!(end.failure, None);
    assert_eq!(
        (
            end.carried,
            end.registry,
            end.outstanding,
            end.kept,
            end.window_bytes
        ),
        (12, 5, 6, 7, 256512)
    );
}

/// A stop and a failure holding spaces, quotes and other fields' markers
/// keep their printed text beside the non-counting terminal a failure
/// leaves; a counting end that names a failure is refused.
#[test]
fn end_text_values_survive_parsing_exactly() {
    let failure = r#"Check { rule: "stale carried=1 kept=2", at: 3 }"#;
    let named = edited(SESSION, "failure=None", &format!("failure=Some({failure})"));
    assert_eq!(
        Session::parse(&named),
        Err(Error::Inconsistent("a counting end names a failure"))
    );
    let text = edited(
        &named,
        "terminal=complete pass fired=03 required=03 counts=true",
        "terminal=complete inconclusive fired=03 required=03 counts=false",
    );
    let text = edited(&text, "stop=goal", "stop=limit same_time");
    let end = Session::parse(&text)
        .expect("the edited fixture parses")
        .end;
    assert_eq!(
        (end.stop.as_str(), end.failure.as_deref()),
        ("limit same_time", Some(failure))
    );
    assert_eq!(end.carried, 12);
}

/// The stdout end line's value parses on its own.
#[test]
fn an_end_line_parses_alone() {
    let line = SESSION
        .lines()
        .nth(1)
        .and_then(|line| line.strip_prefix("end: "));
    let end = End::parse(line.expect("the fixture's end line")).expect("the end parses");
    assert_eq!(Session::parse(SESSION).map(|session| session.end), Ok(end));
}

#[test]
fn session_lines_are_required_once_and_well_formed() {
    for key in ["session", "end"] {
        assert_eq!(
            Session::parse(&without(SESSION, key)),
            Err(Error::Missing(key)),
            "{key}"
        );
        assert_eq!(
            Session::parse(&twice(SESSION, key)),
            Err(Error::Repeated(key.to_owned())),
            "{key}"
        );
    }
    assert_eq!(
        Session::parse(&SESSION[..SESSION.len() - 1]),
        Err(Error::Torn)
    );
    assert_eq!(
        Session::parse(&format!("{SESSION}window: 1\n")),
        Err(Error::Unknown("window".to_owned()))
    );
    for (from, to, error) in [
        ("apply_ms=000000000004", "apply_ms=4", Error::Value("end")),
        ("failure=None", "failure=Nothing", Error::Value("end")),
        ("counts=true", "counts=maybe", Error::Value("end")),
        (" window_bytes=256512", "", Error::Value("end")),
        ("3 windows", "three windows", Error::Value("session")),
        ("stop=goal", "stop=", Error::Value("end")),
        ("stop=goal", "stop=unknown", Error::Value("end")),
        (
            "stop=goal",
            "stop=halted",
            Error::Inconsistent("a counting end stops short of its goal"),
        ),
        ("failure=None", "failure=Some()", Error::Value("end")),
        (
            "counts=true",
            "counts=false",
            Error::Inconsistent("counts disagrees with the terminal"),
        ),
        (
            "fired=03 required=03 counts",
            "fired=01 required=03 counts",
            Error::Inconsistent("counts disagrees with the terminal"),
        ),
        (
            "rested_us=300",
            "rested_us=5101",
            Error::Inconsistent(
                "the rested time exceeds the skipped time or that exceeds the clock",
            ),
        ),
        (
            "skipped_us=5100",
            "skipped_us=5701",
            Error::Inconsistent(
                "the rested time exceeds the skipped time or that exceeds the clock",
            ),
        ),
    ] {
        assert_eq!(
            Session::parse(&edited(SESSION, from, to)),
            Err(error),
            "{from} -> {to}"
        );
    }
    // `rested_us <= skipped_us <= virtual_us` permits equality at both bounds.
    let rested = edited(
        SESSION,
        "virtual_us=5700 skipped_us=5100 rested_us=300",
        "virtual_us=5100 skipped_us=5100 rested_us=5100",
    );
    assert!(Session::parse(&rested).is_ok());
}

fn replay(verdict: &str) -> Result<SessionReplay, Error> {
    SessionReplay::parse(&format!("replay: {verdict}\n"))
}

/// Each verdict keeps the facts its line names: a turn divergence its
/// window, record, virtual time and candidate, and a record divergence its
/// window, record and tag alone.
#[test]
fn each_replay_verdict_keeps_the_facts_it_names() {
    assert_eq!(
        replay(&format!("reproduced, 3 windows, chain {CHAIN}")).map(|replay| match replay {
            SessionReplay::Reproduced { windows, chain } => (windows, chain.to_string()),
            SessionReplay::Diverged(_) => (0, String::new()),
        }),
        Ok((3, CHAIN.to_owned()))
    );
    for (verdict, divergence) in [
        (
            "diverged after the last window: the end differs",
            Divergence::End,
        ),
        (
            "diverged at window 2: 3 windows were committed, 2 replayed",
            Divergence::Windows {
                at: 2,
                committed: 3,
                replayed: 2,
            },
        ),
        (
            "diverged at window 0 record 2: a turn at virtual_us=600 candidate=01100101000000000400000000000000",
            Divergence::Turn {
                window: 0,
                record: 2,
                virtual_us: 600,
                candidate: Candidate("01100101000000000400000000000000".to_owned()),
            },
        ),
        (
            "diverged at window 1 record 0 of tag 1",
            Divergence::Record {
                window: 1,
                record: 0,
                tag: 1,
            },
        ),
    ] {
        assert_eq!(
            replay(verdict),
            Ok(SessionReplay::Diverged(divergence)),
            "{verdict}"
        );
    }
}

#[test]
fn replay_verdicts_outside_their_form_are_refused() {
    for (verdict, error) in [
        (
            "diverged at window 0 record 2: a turn at virtual_us=600 candidate=0110",
            Error::Value("replay"),
        ),
        (
            "diverged at window 0 record 2 of tag x",
            Error::Value("replay"),
        ),
        (
            "diverged at window 0 record 2 of tag 256",
            Error::Value("replay"),
        ),
        ("diverged somewhere", Error::Value("replay")),
        ("reproduced, 3 windows, chain 00", Error::Value("replay")),
        (
            "diverged at window 3: 3 windows were committed, 3 replayed",
            Error::Inconsistent(
                "a window-count divergence names counts that differ, at the smaller",
            ),
        ),
        (
            "diverged at window 1: 3 windows were committed, 2 replayed",
            Error::Inconsistent(
                "a window-count divergence names counts that differ, at the smaller",
            ),
        ),
    ] {
        assert_eq!(replay(verdict), Err(error), "{verdict}");
    }
    let line = "replay: diverged after the last window: the end differs\n";
    assert_eq!(
        SessionReplay::parse(&format!("{line}{line}")),
        Err(Error::Repeated("replay".to_owned()))
    );
    assert_eq!(
        SessionReplay::parse(&line[..line.len() - 1]),
        Err(Error::Torn)
    );
    assert_eq!(
        SessionReplay::parse(&format!("{line}window: 1\n")),
        Err(Error::Unknown("window".to_owned()))
    );
}

#[test]
fn stored_window_and_end_lines_enforce_their_complete_grammars() {
    use super::{SessionEnd, WindowLine};
    let hex = "f524dec13f9c0f31be2de651057fad6650d068a55d69e55f62e58b6df1875dfa";
    let line = format!(
        "window 0 turns=2 digest={hex} chain={hex} verdict=pass carried=1 registry=2 outstanding=3 kept=4 published=5 hits=6 faults=7 reused=8 healed=9"
    );
    let window = WindowLine::parse(&line).unwrap();
    assert_eq!(window.index, 0);
    assert_eq!(window.digest.to_string(), hex);
    assert_eq!(window.chain.to_string(), hex);
    for bad in [
        line.replace("window 0", "window 00"),
        line.replace("window 0", "window 4294967296"),
        line.replace("turns=2", "turns=2 turns=2"),
        line.replace("verdict=pass", "verdict=unknown"),
        line.replace("healed=9", "healed=-1"),
        line.replace("healed=9", "healed=9 extra=1"),
        line.replace(hex, &hex.to_uppercase()),
    ] {
        assert!(WindowLine::parse(&bad).is_err(), "{bad}");
    }
    let end = format!(
        "end: stop=goal terminal=complete pass fired=03 required=03 counts=true turns=2 virtual_us=600 skipped_us=500 rested_us=100 apply_ms=000000000001 failure=None carried=1 registry=2 outstanding=3 kept=4 window_bytes=64 windows=1 chain={hex} tail={hex}\n"
    );
    assert!(WindowLine::parse(&line.replace("turns=2", "turns=4294967296")).is_ok());
    for counter in ["carried=1", "registry=2", "outstanding=3", "kept=4"] {
        let key = counter.split_once('=').unwrap().0;
        assert!(SessionEnd::parse(&end.replace(counter, &format!("{key}=4294967296"))).is_ok());
    }
    assert!(WindowLine::parse(&line).unwrap().passed);
    assert!(
        !WindowLine::parse(&line.replace("verdict=pass", "verdict=failed"))
            .unwrap()
            .passed
    );
    for counter in [
        "carried=1",
        "registry=2",
        "outstanding=3",
        "kept=4",
        "published=5",
        "hits=6",
        "faults=7",
        "reused=8",
        "healed=9",
    ] {
        let key = counter.split_once('=').unwrap().0;
        assert!(WindowLine::parse(&line.replace(counter, &format!("{key}=4294967295"))).is_ok());
        assert_eq!(
            WindowLine::parse(&line.replace(counter, &format!("{key}=4294967296"))),
            Err(Error::Value("window"))
        );
    }
    assert_eq!(SessionEnd::parse(end.trim_end()), Err(Error::Torn));
    assert_eq!(
        SessionEnd::parse(&end.replace("end: ", "finish: ")),
        Err(Error::Value("end"))
    );
    assert_eq!(
        SessionEnd::parse(&end.replace(" windows=", "\n windows=")),
        Err(Error::Value("end"))
    );
    let parsed = SessionEnd::parse(&end).unwrap();
    assert_eq!(parsed.windows, 1);
    assert_eq!(parsed.tail.to_string(), hex);
    let timed =
        SessionEnd::parse(&end.replace("apply_ms=000000000001", "apply_ms=000000000002")).unwrap();
    assert!(parsed.reproduces(&timed));
    for bad in [
        end.trim_end().to_owned(),
        end.replace("windows=1", "windows=1 windows=1"),
        end.replace("window_bytes=64", "window_bytes=64 extra=1"),
        end.replace("tail=", "tail=0"),
        end.replace('\n', "\r\n"),
    ] {
        assert!(SessionEnd::parse(&bad).is_err(), "{bad}");
    }
}

#[test]
fn panicked_session_ends_keep_the_complete_identity_and_footer() {
    use super::{SessionEnd, SessionEnding};
    let hex = "f524dec13f9c0f31be2de651057fad6650d068a55d69e55f62e58b6df1875dfa";
    let panic = "src/world.rs:1:2: windows=99 apply_ms=000000000001";
    let line = format!("end: panicked {panic} windows=1 chain={hex} tail={hex}\n");
    let parsed = SessionEnd::parse(&line).unwrap();
    assert_eq!(parsed.end, SessionEnding::Panicked(panic.into()));
    assert_eq!(parsed.windows, 1);
    assert!(parsed.reproduces(&parsed));
    let changed =
        SessionEnd::parse(&line.replace("apply_ms=000000000001", "apply_ms=000000000002")).unwrap();
    assert!(!parsed.reproduces(&changed));
    assert!(SessionEnd::parse(line.trim_end()).is_err());
    assert!(SessionEnd::parse(&line.replace(panic, "")).is_err());
}
