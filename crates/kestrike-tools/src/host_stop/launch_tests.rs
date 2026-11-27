use std::time::Duration;

use super::{TAIL, tail, whole_seconds};

/// The CLI's timeouts are the cut in whole seconds rounded up and at least 1, saturating at the
/// largest count.
#[test]
fn the_cut_rounds_up_to_whole_seconds_and_at_least_1() {
    for (cut, seconds) in [
        (Duration::ZERO, 1),
        (Duration::from_nanos(1), 1),
        (Duration::from_secs(1), 1),
        (Duration::new(1, 1), 2),
        (Duration::from_millis(7500), 8),
        (Duration::MAX, u64::MAX),
    ] {
        assert_eq!(whole_seconds(cut), seconds, "{cut:?}");
    }
}

/// The tail counts Unicode scalar values, so a text of multi-byte characters keeps 400 of them.
#[test]
fn the_tail_keeps_the_last_400_characters() {
    assert_eq!(TAIL, 400);
    for length in [0, 399, 400, 401, 800] {
        let text = "\u{e9}".repeat(length);
        assert_eq!(tail(&text).chars().count(), length.min(TAIL), "{length}");
    }
    let text = format!("{}END", "a\u{e9}".repeat(300));
    let expected: String = text.chars().skip(603 - TAIL).collect();
    assert_eq!(tail(&text), expected);
    assert!(expected.starts_with('\u{e9}') && expected.ends_with("END"));
}
