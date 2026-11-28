use super::posix_seconds;

/// Each calendar second reads as its POSIX seconds, and a second `time.strptime` refuses reads as
/// none: values recorded from `calendar.timegm(time.strptime(text, format))`, `format` being
/// `"%Y-%m-%dT%H:%M:%S"` for a text with `T` and `"%Y-%m-%d %H:%M:%S"` for one with a space.
#[test]
fn a_calendar_second_is_its_posix_seconds_and_a_missing_day_is_none() {
    let cases = [
        ("1970-01-01T00:00:00", Some(0)),
        ("1969-12-31T23:59:59", Some(-1)),
        ("0001-01-01T00:00:00", Some(-62_135_596_800)),
        ("9999-12-31T23:59:59", Some(253_402_300_799)),
        ("2400-02-29T12:00:00", Some(13_574_606_400)),
        ("2000-02-29 00:00:00", Some(951_782_400)),
        ("1970-01-01T00:00:60", Some(60)),
        ("1970-01-01T00:00:61", Some(61)),
        ("1970-01-01T00:00:62", None),
        ("2100-02-29T00:00:00", None),
        ("1900-02-29T00:00:00", None),
        ("2026-04-31T00:00:00", None),
        ("0000-06-01T00:00:00", None),
        ("2026-00-01T00:00:00", None),
        ("2026-13-01T00:00:00", None),
        ("2026-01-00T00:00:00", None),
        ("2026-11-27T24:00:00", None),
        ("2026-11-27T23:60:00", None),
        ("2026-11-27T23:59", None),
        ("2026/11/27T23:59:59", None),
        ("2026-11-2xT23:59:59", None),
        ("2026-11-27T23:59:5é", None),
    ];
    for (text, seconds) in cases {
        assert_eq!(posix_seconds(text), seconds, "{text}");
    }
}
