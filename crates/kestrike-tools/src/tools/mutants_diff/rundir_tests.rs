use super::rundir::utc_stamp_at;

#[test]
fn the_stamp_is_the_utc_calendar_time_of_its_seconds() {
    for (seconds, stamp) in [
        (0, "19700101T000000Z-"),
        (951_782_400, "20000229T000000Z-"),
        (1_709_251_200, "20240301T000000Z-"),
        (1_735_689_599, "20241231T235959Z-"),
        (4_107_542_399, "21000228T235959Z-"),
    ] {
        assert_eq!(
            utc_stamp_at(seconds),
            stamp,
            "time.strftime('%Y%m%dT%H%M%SZ-', time.gmtime({seconds}))"
        );
    }
}
