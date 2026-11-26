use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Clock, SystemClock, basic, parse_utc};
use crate::loopback::rfc3339;

#[test]
fn the_signing_suite_instant_formats_as_its_amz_date() {
    let at = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
    assert_eq!(basic(at), "20150830T123600Z");
    assert_eq!(parse_utc("2015-08-30T12:36:00Z"), Some(at));
}

#[test]
fn formatted_times_parse_back_to_themselves() {
    for seconds in (0..=13_514_400_000_u64).step_by(3_599_993) {
        let at = UNIX_EPOCH + Duration::from_secs(seconds);
        let rfc = rfc3339(at);
        assert_eq!(parse_utc(&rfc), Some(at), "{rfc}");
    }
}

#[test]
fn a_leap_day_parses_only_in_a_leap_year() {
    assert!(parse_utc("2024-02-29T00:00:00Z").is_some());
    assert!(parse_utc("2000-02-29T00:00:00Z").is_some());
    assert!(parse_utc("2023-02-29T00:00:00Z").is_none());
    assert!(parse_utc("2100-02-29T00:00:00Z").is_none());
}

/// The fixed samples cover the first and last seconds of February 29,
/// 2000, and midnight UTC on March 1, 2100, and February 29, 2024.
#[test]
fn the_fixed_samples_format_and_parse_as_their_known_text() {
    let samples = [
        (951_782_400, "20000229T000000Z", "2000-02-29T00:00:00Z"),
        (951_868_799, "20000229T235959Z", "2000-02-29T23:59:59Z"),
        (4_107_542_400, "21000301T000000Z", "2100-03-01T00:00:00Z"),
        (1_709_164_800, "20240229T000000Z", "2024-02-29T00:00:00Z"),
    ];
    for (seconds, amz, rfc) in samples {
        let at = UNIX_EPOCH + Duration::from_secs(seconds);
        assert_eq!(basic(at), amz);
        assert_eq!(parse_utc(rfc), Some(at), "{rfc}");
    }
}

#[test]
fn text_outside_the_exact_form_or_before_the_epoch_parses_to_nothing() {
    for text in [
        "",
        "2017-05-17T15:09:54",
        "2017-05-17 15:09:54Z",
        "2017-05-17T15:09:54.000Z",
        "2017-05-17T15:09:54+00:00",
        "2017-5-17T15:09:54Z",
        "+017-05-17T15:09:54Z",
        "2017-00-17T15:09:54Z",
        "2017-13-17T15:09:54Z",
        "2017-04-31T15:09:54Z",
        "2024-02-30T15:09:54Z",
        "2017-05-00T15:09:54Z",
        "2017-05-17T24:00:00Z",
        "2017-05-17T15:60:00Z",
        "2017-05-17T15:09:60Z",
        "1969-12-31T23:59:59Z",
    ] {
        assert_eq!(parse_utc(text), None, "{text}");
    }
}

#[test]
fn a_time_before_the_epoch_formats_as_the_epoch() {
    assert_eq!(
        basic(UNIX_EPOCH - Duration::from_secs(1)),
        "19700101T000000Z"
    );
}

/// The reading lies within a minute of the system time read beside it; the
/// minute allows for a step of the system clock between the two.
#[test]
fn the_system_clock_reads_the_system_time() {
    let beside = SystemTime::now();
    let read = SystemClock.now();
    let apart = match read.duration_since(beside) {
        Ok(ahead) => ahead,
        Err(behind) => behind.duration(),
    };
    assert!(apart < Duration::from_secs(60), "{apart:?}");
}
