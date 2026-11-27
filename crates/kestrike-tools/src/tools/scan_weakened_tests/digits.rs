//! A decimal digit is a code point of category `Nd`. Unicode assigns these digits in runs of ten from zero, so
//! a digit's value is its offset in its run of `Nd` code points, modulo ten.

use crate::json::{Integer, MAX_INTEGER_DIGITS};
use crate::rust_text::is_digit;

use super::Failure;

/// The code points outside category `Nd` for which Python 3.9's `str.isdigit()` holds, under Unicode 13.0.
const OTHER_DIGITS: [(u32, u32); 20] = [
    (0xb2, 0xb3),
    (0xb9, 0xb9),
    (0x1369, 0x1371),
    (0x19da, 0x19da),
    (0x2070, 0x2070),
    (0x2074, 0x2079),
    (0x2080, 0x2089),
    (0x2460, 0x2468),
    (0x2474, 0x247c),
    (0x2488, 0x2490),
    (0x24ea, 0x24ea),
    (0x24f5, 0x24fd),
    (0x24ff, 0x24ff),
    (0x2776, 0x277e),
    (0x2780, 0x2788),
    (0x278a, 0x2792),
    (0x10a40, 0x10a43),
    (0x10e60, 0x10e68),
    (0x11052, 0x1105a),
    (0x1f100, 0x1f10a),
];

/// `integer` reads `digits`, decimal digits and underscores, as a nonnegative integer.
///
/// # Errors
///
/// [`Failure::Digits`] when `digits` holds more than [`MAX_INTEGER_DIGITS`] digits.
pub fn integer(digits: &str) -> Result<Integer, Failure> {
    let ascii: String = digits
        .chars()
        .filter(|&c| c != '_')
        .map(|c| char::from(b'0' + value(c)))
        .collect();
    if ascii.len() > MAX_INTEGER_DIGITS {
        return Err(Failure::Digits(ascii.len()));
    }
    Ok(Integer::from_digits(false, &ascii).expect("a digit maps to an ASCII digit"))
}

fn value(c: char) -> u8 {
    if c.is_ascii_digit() {
        return c as u8 - b'0';
    }
    let offset = (1..=u32::from(c))
        .take_while(|&back| char::from_u32(u32::from(c) - back).is_some_and(is_digit))
        .count();
    (offset % 10) as u8
}

pub fn is_digits(text: impl IntoIterator<Item = u32>) -> bool {
    let mut any = false;
    for code in text {
        let other = OTHER_DIGITS
            .iter()
            .any(|&(low, high)| (low..=high).contains(&code));
        if !other && !char::from_u32(code).is_some_and(is_digit) {
            return false;
        }
        any = true;
    }
    any
}
