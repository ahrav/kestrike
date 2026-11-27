//! A UTC calendar second as POSIX seconds, for the ISO times of an operator file, a record's
//! `LaunchTime` and a stop's transition reason. A second is admitted when `time.strptime` admits it:
//! a year from 1 to 9999, a month from 1 to 12, a day of that month, an hour to 23, a minute to 59
//! and a second to 61.

/// `posix_seconds` is the POSIX seconds of the calendar second that `text` spells as
/// `YYYY-MM-DD?HH:MM:SS`, any one character standing at `?`, or `None` for a second the calendar
/// lacks or a text off that layout.
pub fn posix_seconds(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let laid_out = bytes.len() == 19
        && [(4, b'-'), (7, b'-'), (13, b':'), (16, b':')]
            .iter()
            .all(|&(at, separator)| bytes[at] == separator);
    if !laid_out {
        return None;
    }
    let number = |at: usize, digits: usize| -> Option<i64> {
        let part = text.get(at..at + digits)?;
        part.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (number(0, 4)?, number(5, 2)?, number(8, 2)?);
    let (hour, minute, second) = (number(11, 2)?, number(14, 2)?, number(17, 2)?);
    let ranged = (1..=9999).contains(&year)
        && (1..=days_in(year, month)?).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 61;
    ranged.then(|| days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// The days of `month` in `year`, or `None` for a month outside 1 to 12.
fn days_in(year: i64, month: i64) -> Option<i64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if leap => Some(29),
        2 => Some(28),
        _ => None,
    }
}

/// The days from 1970-01-01 to the day of the proleptic Gregorian calendar, by eras of 400 years
/// that start on 1 March (Hinnant, *chrono-Compatible Low-Level Date Algorithms*, `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
#[path = "calendar_tests.rs"]
mod tests;
