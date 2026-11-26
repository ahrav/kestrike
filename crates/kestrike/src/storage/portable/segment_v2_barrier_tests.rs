//! A native caller of the segment reader's attempt, kept in the linked library-test executable for `scripts/scan-barriers.py`: the attempt's acquire barriers after the first header read and after the body read.
//!
//! The caller is `inline(never)` and monomorphic over the reader's fake host, takes its reader through [`black_box`], and reaches the barriers only through `Reader::attempt`, which is `#[inline(always)]` as is the barrier helper, so both barriers land in the caller's own extent. The scan establishes that a sufficient barrier is present in that extent; the number of barriers and their places between the three reads rest on review of `Reader::attempt`.
//!
//! The test runs the caller over the synchronized fixture, which yields its generation and decoded body, and over a torn script whose closing header carries a later generation, which yields a retry. The fake host serves every read in program order, so the torn case exercises the attempt's generation check, and the barriers' effect on hardware ordering rests on the scan and the reader's module argument.

use std::hint::black_box;

use super::clock::ClockScale;
use super::expiry::NANOS_PER_SECOND;
use super::segment_v2::{Attempt, Body, Reader};
use super::segment_v2_tests::{Fake, LIMIT, SYNCED, image};

#[inline(never)]
fn segment_attempt(reader: &mut Reader<Fake>) -> Attempt {
    reader.attempt()
}

/// The caller decodes the synchronized fixture (`as_of` 99 s, `void_after` 110 s, a 500 µs bound, marker `0xD15C`, 50,000 ppb, synchronized, support on) as `Fresh(4, body)`, and retries an attempt whose closing header carries generation 6.
#[test]
fn the_attempt_caller_reads_a_synchronized_body_and_retries_a_torn_one() {
    let mut reader = Reader::new(Fake::holding(SYNCED), ClockScale::UtcSmeared, 3, LIMIT)
        .expect("a reader on an admitted target");
    let synced = Body {
        as_of: 99 * NANOS_PER_SECOND,
        void_after: 110 * NANOS_PER_SECOND,
        bound: 500_000,
        marker: 0xD15C,
        drift_ppb: 50_000,
        status: 1,
        disruption_support: true,
    };
    assert_eq!(
        segment_attempt(black_box(&mut reader)),
        Attempt::Fresh(4, synced)
    );
    let mut torn = image(SYNCED);
    torn[14..16].copy_from_slice(&6_u16.to_le_bytes());
    reader
        .host_mut()
        .then([Some(image(SYNCED)), Some(image(SYNCED)), Some(torn)]);
    assert_eq!(
        segment_attempt(black_box(&mut reader)),
        Attempt::Retry { short: false }
    );
}
