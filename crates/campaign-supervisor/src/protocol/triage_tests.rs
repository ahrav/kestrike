//! Literal result lines pin replay positions, panic identities and reducer bounds.
use super::{Error, ReduceResult, ReplayResult};
#[test]
fn replay_lines_preserve_the_claim_position_and_panic_text() {
    assert_eq!(
        ReplayResult::parse(
            "replay: reproduced, complete violation fired=03 required=03, violating Bytes\n"
        )
        .expect("replay"),
        ReplayResult::Reproduced("complete violation fired=03 required=03, violating Bytes".into())
    );
    assert_eq!(
        ReplayResult::parse("replay: diverged at semantic record 9: Identity\n")
            .expect("divergence"),
        ReplayResult::Diverged {
            at: Some(9),
            reason: "Identity".into()
        }
    );
    assert_eq!(
        ReplayResult::parse("replay: diverged at the result: Trailing\n").expect("divergence"),
        ReplayResult::Diverged {
            at: None,
            reason: "Trailing".into()
        }
    );
    assert_eq!(
        ReplayResult::parse("replay: the run panicked at src/x.rs:1:2: x, y\n").expect("panic"),
        ReplayResult::Panicked("src/x.rs:1:2: x, y".into())
    );
}
#[test]
fn reproduced_claims_agree_with_terminal_and_breach_facts() {
    let listing = super::Listing::parse(super::fixture::LISTING).expect("listing");
    for (terminal, cause, claim) in [
        (
            "complete violation fired=03 required=03",
            "violation, violating Bytes",
            "complete violation fired=03 required=03, violating Bytes",
        ),
        (
            "complete violation fired=03 required=03",
            "violation, a failing Digest audit record",
            "complete violation fired=03 required=03, a failing Digest audit record",
        ),
        (
            "infrastructure cap",
            "infrastructure cap, violating Bytes, stop goal",
            "infrastructure cap, violating Bytes",
        ),
        (
            "infrastructure defect",
            "infrastructure defect, stop defect choice",
            "infrastructure defect",
        ),
    ] {
        let printed = super::fixture::COUNTING
            .replace("complete pass fired=03 required=03", terminal)
            .replace("counts: true", "counts: false")
            + &format!("cause: {cause}\n");
        let summary = super::Summary::parse(&printed, &listing).expect("summary");
        let result = ReplayResult::parse(&format!("replay: reproduced, {claim}\n")).expect("claim");
        assert!(result.agrees(&summary), "{claim}: {cause}");
        assert!(
            !ReplayResult::Reproduced("complete pass fired=03 required=03".into()).agrees(&summary)
        );
        assert!(
            !ReplayResult::Reproduced(format!("{terminal}, violating Restart")).agrees(&summary)
        );
    }
}

#[test]
fn reduction_lines_preserve_all_fields() {
    for (suffix, bounded, panic) in [
        ("", false, None),
        (", bounded", true, None),
        (
            ", the run panicked at src/x.rs:1:2: boom",
            false,
            Some("src/x.rs:1:2: boom"),
        ),
        (
            ", bounded, the run panicked at src/x.rs:1:2: boom",
            true,
            Some("src/x.rs:1:2: boom"),
        ),
    ] {
        assert_eq!(
            ReduceResult::parse(&format!(
                "reduce: reduced to 250 records, scenario ab{suffix}\n"
            ))
            .expect("reduction"),
            ReduceResult {
                records: 250,
                scenario: "ab".into(),
                bounded,
                panic: panic.map(str::to_owned)
            }
        );
    }
}
#[test]
fn torn_repeated_foreign_and_malformed_results_are_refused() {
    for line in [
        "replay: reproduced\n",
        "replay: reproduced, \n",
        "replay: diverged at semantic record x: bad\n",
        "replay: diverged at the result: \n",
        "replay: the run panicked at \n",
    ] {
        assert!(ReplayResult::parse(line).is_err(), "{line}");
    }
    for line in [
        "reduce: reduced to x records, scenario ab\n",
        "reduce: reduced to 1 records, scenario \n",
        "reduce: reduced to 1 records, scenario ab, other\n",
    ] {
        assert!(ReduceResult::parse(line).is_err(), "{line}");
    }
    for form in [
        "replay: reproduced, complete pass",
        "reduce: reduced to 1 records, scenario ab",
    ] {
        let parse = |text: &str| {
            if form.starts_with("replay") {
                ReplayResult::parse(text).map(|_| ())
            } else {
                ReduceResult::parse(text).map(|_| ())
            }
        };
        assert!(matches!(parse(form), Err(Error::Torn)));
        assert!(matches!(
            parse(&format!("{form}\n{form}\n")),
            Err(Error::Repeated(_))
        ));
        assert!(matches!(
            parse(&format!("{form}\nforeign: x\n")),
            Err(Error::Unknown(_))
        ));
    }
}
