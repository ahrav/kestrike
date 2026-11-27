//! Exact decimal numbers: a sign, decimal digits and a power of ten, with the sum, the difference, the
//! order and the whole-quotient test of Python's fractions.
//!
//! A [`Decimal`] holds its digits with no leading or trailing zero, and zero as no digits and no sign, so
//! two decimals of one value are equal and [`Ord`] orders them by value. The public constructors take a
//! JSON integer or a finite float's shortest form, so every exponent lies from -1074 to
//! [`MAX_INTEGER_DIGITS`](crate::json::MAX_INTEGER_DIGITS) and every sum or difference of such numbers is
//! exact.

use std::cmp::Ordering;
use std::ops::{Add, Sub};

use crate::json::Integer;
use crate::python::repr_float;

/// The largest adjusted exponent of Python's `decimal` module, `MAX_EMAX`.
const EMAX: i128 = 999_999_999_999_999_999;
/// The smallest exponent of Python's `decimal` module, `MIN_EMIN - (MAX_PREC - 1)`.
const ETINY: i128 = -1_999_999_999_999_999_997;
/// A bound past both decimal limits, at which a literal's exponent saturates.
const SATURATED: i128 = 10_i128.pow(20);

/// `Decimal` is an exact decimal value in the normal form the module states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decimal {
    negative: bool,
    /// Decimal digits, each 0 to 9, most significant first; empty for zero.
    digits: Vec<u8>,
    exponent: i64,
}

impl Decimal {
    fn zero() -> Self {
        Self {
            negative: false,
            digits: Vec::new(),
            exponent: 0,
        }
    }

    /// `normal` strips leading and trailing zeros from `digits`, moving the trailing ones into the exponent.
    fn normal(negative: bool, mut digits: Vec<u8>, exponent: i64) -> Self {
        let lead = digits.iter().take_while(|&&digit| digit == 0).count();
        digits.drain(..lead);
        let trail = digits.iter().rev().take_while(|&&digit| digit == 0).count();
        digits.truncate(digits.len() - trail);
        if digits.is_empty() {
            return Self::zero();
        }
        let exponent = exponent
            .checked_add(i64::try_from(trail).expect("a digit count fits an i64"))
            .expect("a normalized exponent fits an i64");
        Self {
            negative,
            digits,
            exponent,
        }
    }

    pub(crate) fn from_integer(integer: &Integer) -> Self {
        let shown = integer.to_string();
        let (negative, digits) = match shown.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, shown.as_str()),
        };
        Self::normal(
            negative,
            digits.bytes().map(|byte| byte - b'0').collect(),
            0,
        )
    }

    /// `from_float` is the decimal value of the shortest form of `value`, or `None` for a non-finite float.
    pub(crate) fn from_float(value: f64) -> Option<Self> {
        if !value.is_finite() {
            return None;
        }
        Some(
            Self::literal(&repr_float(value))
                .expect("a float's shortest form lies in the decimal range"),
        )
    }

    /// `literal` is the value of a JSON number token, as Python's `decimal.Decimal` reads the token, or
    /// `None` when that constructor refuses it: a zero whose exponent passes `EMAX` or lies below `ETINY`,
    /// or a nonzero value whose adjusted exponent passes `EMAX` or whose exponent lies below `ETINY`.
    fn literal(token: &str) -> Option<Self> {
        let (negative, rest) = match token.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, token),
        };
        let (mantissa, power) = match rest.find(['e', 'E']) {
            Some(at) => (&rest[..at], Some(&rest[at + 1..])),
            None => (rest, None),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let power = power.map_or(0, saturating_exponent);
        let fraction_digits = i128::try_from(fraction.len()).expect("a length fits an i128");
        let exponent = power - fraction_digits;
        let digits: Vec<u8> = whole
            .bytes()
            .chain(fraction.bytes())
            .map(|byte| byte - b'0')
            .collect();
        let significant = digits.iter().skip_while(|&&digit| digit == 0).count();
        let in_range = if significant == 0 {
            (ETINY..=EMAX).contains(&exponent)
        } else {
            let adjusted =
                exponent + i128::try_from(significant).expect("a count fits an i128") - 1;
            adjusted <= EMAX && exponent >= ETINY
        };
        if !in_range {
            return None;
        }
        let exponent =
            i64::try_from(exponent).expect("an exponent in the decimal range fits an i64");
        Some(Self::normal(negative, digits, exponent))
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.digits.is_empty()
    }

    /// `whole_quotient` is the whole number `self / divisor` when it lies from 1 to `most`, and `None`
    /// otherwise; a zero divisor gives `None`.
    pub(crate) fn whole_quotient(&self, divisor: &Self, most: u32) -> Option<u32> {
        if self.is_zero() || divisor.is_zero() || self.negative != divisor.negative {
            return None;
        }
        let low = self.exponent.min(divisor.exponent);
        let dividend = shifted(&self.digits, self.exponent - low);
        let divisor = shifted(&divisor.digits, divisor.exponent - low);
        let (mut floor, mut ceiling) = (1_u32, most);
        while floor <= ceiling {
            let middle = floor + (ceiling - floor) / 2;
            match compare_whole(&times(&divisor, middle), &dividend) {
                Ordering::Equal => return Some(middle),
                Ordering::Less => floor = middle.checked_add(1)?,
                // `middle >= floor >= 1`, so the subtraction stays in range and a `middle` of 1 ends the loop.
                Ordering::Greater => ceiling = middle - 1,
            }
        }
        None
    }

    /// `whole_digits` writes a whole number's digits with its sign, and gives `None` for any other value.
    pub(crate) fn whole_digits(&self) -> Option<String> {
        if self.is_zero() {
            return Some("0".to_owned());
        }
        let zeros = usize::try_from(self.exponent).ok()?;
        let sign = if self.negative { "-" } else { "" };
        let digits: String = self
            .digits
            .iter()
            .map(|digit| char::from(b'0' + digit))
            .collect();
        Some(format!("{sign}{digits}{}", "0".repeat(zeros)))
    }

    /// `nearest` is the double nearest the value, rounded half to even; a value past the largest double
    /// gives an infinity.
    pub(crate) fn nearest(&self) -> f64 {
        let sign = if self.negative { "-" } else { "" };
        let digits: String = self
            .digits
            .iter()
            .map(|digit| char::from(b'0' + digit))
            .collect();
        if digits.is_empty() {
            return 0.0;
        }
        format!("{sign}{digits}e{}", self.exponent)
            .parse()
            .expect("a decimal parses as an f64")
    }

    fn negated(&self) -> Self {
        Self {
            negative: !self.negative && !self.is_zero(),
            ..self.clone()
        }
    }
}

/// The exponent of a literal's digits, saturated at [`SATURATED`] in either direction.
fn saturating_exponent(power: &str) -> i128 {
    let (negative, digits) = match power.as_bytes().first() {
        Some(b'-') => (true, &power[1..]),
        Some(b'+') => (false, &power[1..]),
        _ => (false, power),
    };
    let magnitude = digits.bytes().fold(0_i128, |value, byte| {
        (value * 10 + i128::from(byte - b'0')).min(SATURATED)
    });
    if negative { -magnitude } else { magnitude }
}

/// `digits` followed by `zeros` zeros.
fn shifted(digits: &[u8], zeros: i64) -> Vec<u8> {
    let zeros = usize::try_from(zeros).expect("an alignment is no negative shift");
    let mut out = Vec::with_capacity(digits.len() + zeros);
    out.extend_from_slice(digits);
    out.resize(digits.len() + zeros, 0);
    out
}

/// `digits × factor`, with no leading zero.
fn times(digits: &[u8], factor: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(digits.len() + 10);
    let mut carry = 0_u64;
    for &digit in digits.iter().rev() {
        let product = u64::from(digit) * u64::from(factor) + carry;
        out.push(u8::try_from(product % 10).expect("a remainder of ten is a digit"));
        carry = product / 10;
    }
    while carry > 0 {
        out.push(u8::try_from(carry % 10).expect("a remainder of ten is a digit"));
        carry /= 10;
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    out.reverse();
    out
}

/// The order of two whole numbers, each written with no leading zero.
fn compare_whole(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

impl Ord for Decimal {
    fn cmp(&self, other: &Self) -> Ordering {
        let difference = self - other;
        if difference.is_zero() {
            Ordering::Equal
        } else if difference.negative {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for Decimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Add for &Decimal {
    type Output = Decimal;

    fn add(self, other: &Decimal) -> Decimal {
        sum(self, other)
    }
}

impl Sub for &Decimal {
    type Output = Decimal;

    fn sub(self, other: &Decimal) -> Decimal {
        sum(self, &other.negated())
    }
}

/// The exact sum of two decimals.
fn sum(this: &Decimal, other: &Decimal) -> Decimal {
    if this.is_zero() {
        return other.clone();
    }
    if other.is_zero() {
        return this.clone();
    }
    let low = this.exponent.min(other.exponent);
    let left = shifted(&this.digits, this.exponent - low);
    let right = shifted(&other.digits, other.exponent - low);
    if this.negative == other.negative {
        return Decimal::normal(this.negative, add_whole(&left, &right), low);
    }
    match compare_whole(&left, &right) {
        Ordering::Equal => Decimal::zero(),
        Ordering::Greater => Decimal::normal(this.negative, sub_whole(&left, &right), low),
        Ordering::Less => Decimal::normal(other.negative, sub_whole(&right, &left), low),
    }
}

fn add_whole(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(left.len().max(right.len()) + 1);
    let (mut left, mut right) = (left.iter().rev(), right.iter().rev());
    let mut carry = 0;
    loop {
        let (a, b) = (left.next(), right.next());
        if a.is_none() && b.is_none() {
            break;
        }
        let sum = a.copied().unwrap_or(0) + b.copied().unwrap_or(0) + carry;
        out.push(sum % 10);
        carry = sum / 10;
    }
    if carry > 0 {
        out.push(carry);
    }
    out.reverse();
    out
}

/// `left - right` for whole numbers with `left >= right`.
fn sub_whole(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(left.len());
    let mut right = right.iter().rev();
    let mut borrow = 0;
    for &digit in left.iter().rev() {
        let take = right.next().copied().unwrap_or(0) + borrow;
        if digit >= take {
            out.push(digit - take);
            borrow = 0;
        } else {
            out.push(digit + 10 - take);
            borrow = 1;
        }
    }
    out.reverse();
    out
}

/// `spells_shortest` holds when the JSON number `token` has the decimal value of the shortest form of
/// `value`, its nearest double, as Python's `decimal.Decimal` reads both; a token whose exponent lies past
/// that module's range fails.
pub(crate) fn spells_shortest(token: &str, value: f64) -> bool {
    Decimal::literal(token).is_some_and(|exact| Decimal::from_float(value) == Some(exact))
}
