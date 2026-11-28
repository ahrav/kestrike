use std::time::Duration;

use super::seconds;

/// For 1_799_999_999 s plus 999_999_880 ns, `seconds` casts the total nanoseconds to `f64` and
/// divides by 1e9, yielding 1.8e9; `as_secs_f64` yields less.
#[test]
fn wall_seconds_divide_the_nanosecond_count() {
    assert_eq!(seconds(Duration::from_secs(1_800_000_000)), 1.8e9);
    assert_eq!(seconds(Duration::new(1_799_999_999, 999_999_880)), 1.8e9);
    assert!(Duration::new(1_799_999_999, 999_999_880).as_secs_f64() < 1.8e9);
    assert_eq!(seconds(Duration::from_millis(1500)), 1.5);
    assert_eq!(seconds(Duration::ZERO), 0.0);
}
