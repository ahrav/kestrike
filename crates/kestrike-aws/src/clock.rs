//! `basic` formats wall time as a SigV4 timestamp and `parse_utc` reads
//! the RFC 3339 form `YYYY-MM-DDTHH:MM:SSZ`. Both forms are whole seconds
//! in UTC.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `Clock` supplies the UTC wall time that dates each signature and that
/// credential expiry is compared against. A live call needs a clock that
/// tracks the time AWS keeps; a test clock supplies time consistent with
/// its fixtures. Readings may step in either direction. Call deadlines run
/// on `Instant`, so a clock reading never moves a deadline.
pub trait Clock {
    fn now(&self) -> SystemTime;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

const DAY: u64 = 86_400;

/// `basic` formats `time` as a SigV4 timestamp (`YYYYMMDDTHHMMSSZ`) and
/// writes any time before the epoch as `19700101T000000Z`.
pub(crate) fn basic(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day) = civil(seconds / DAY);
    let of_day = seconds % DAY;
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        of_day / 3600,
        of_day / 60 % 60,
        of_day % 60
    )
}

/// `parse_utc` accepts UTC timestamps in the exact form
/// `YYYY-MM-DDTHH:MM:SSZ` and returns `None` for any other text, an invalid
/// date or a time before the epoch.
pub(crate) fn parse_utc(text: &str) -> Option<SystemTime> {
    let bytes = text.as_bytes();
    let shape = b"dddd-dd-ddTdd:dd:ddZ";
    if bytes.len() != shape.len()
        || !bytes.iter().zip(shape).all(|(&byte, &want)| match want {
            b'd' => byte.is_ascii_digit(),
            _ => byte == want,
        })
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| {
        bytes[range]
            .iter()
            .fold(0_u64, |value, digit| value * 10 + u64::from(digit - b'0'))
    };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let (hour, minute, second) = (number(11..13), number(14..16), number(17..19));
    if year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > month_days(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let seconds = days(year, month, day) * DAY + hour * 3600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn month_days(year: u64, month: u64) -> u64 {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// The two conversions below count days in 400-year eras whose years start
// in March, so a leap day is the last day of its year (Hinnant,
// *chrono-Compatible Low-Level Date Algorithms*, 2013). The epoch is day
// 719,468 of that count.
const EPOCH_DAY: u64 = 719_468;

/// `days` counts the days from the epoch to `year-month-day`, a date on or
/// after the epoch.
fn days(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let (era, of_era) = (year / 400, year % 400);
    let of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let of_era = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    era * 146_097 + of_era - EPOCH_DAY
}

/// `civil` returns the year, month and day `days` after the epoch.
fn civil(days: u64) -> (u64, u64, u64) {
    let days = days + EPOCH_DAY;
    let (era, of_era) = (days / 146_097, days % 146_097);
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
#[path = "clock_tests.rs"]
mod tests;
