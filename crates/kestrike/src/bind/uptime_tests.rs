//! Boot-tick conversion of procfs `uptime` text: every arithmetic edge
//! against a `u128` reference, malformed text and tick rates, and the
//! procfs file the walk reads through the fixture's `proc` root.

use super::fixture::Fixture;
use super::walk::{boot_ticks, uptime_ticks};

/// The ticks `seconds` and `hundredths` make at `hz` in `u128`, or `None`
/// when an intermediate value, `seconds * 100`, its sum with `hundredths`
/// or that sum times `hz`, passes `u64::MAX`.
fn reference(seconds: u64, hundredths: u64, hz: u64) -> Option<u64> {
    let max = u128::from(u64::MAX);
    let scaled = u128::from(seconds) * 100;
    let centiseconds = scaled + u128::from(hundredths);
    let product = centiseconds.saturating_mul(u128::from(hz));
    (scaled <= max && centiseconds <= max && product <= max).then_some((product / 100) as u64)
}

/// Seconds, hundredths and tick rates at each overflow site and either side
/// of it convert as the `u128` reference says.
#[test]
fn ib_uptime_arithmetic_matches_the_widened_floor_at_every_edge() {
    let max = u64::MAX;
    let seconds = [
        0,
        1,
        100,
        12_345,
        max / 100 - 1,
        max / 100,
        max / 100 + 1,
        max,
    ];
    let hundredths = [0, 1, 15, 16, 50, 99];
    let rates = [1, 100, 250, 1000, max / 10_000, max / 100, max];
    let (mut converted, mut refused) = (0, 0);
    for s in seconds {
        for h in hundredths {
            for hz in rates {
                let text = format!("{s}.{h:02} 400.00\n");
                let hz_long = libc::c_long::try_from(hz).unwrap_or(libc::c_long::MAX);
                let expected = reference(s, h, u64::try_from(hz_long).unwrap());
                assert_eq!(
                    uptime_ticks(&text, hz_long),
                    expected,
                    "{text:?} at {hz_long}"
                );
                match expected {
                    Some(_) => converted += 1,
                    None => refused += 1,
                }
            }
        }
    }
    assert!(converted > 0 && refused > 0);
    // `seconds * 100` alone overflows; the sum overflows at `.16` and fits
    // at `.15`; the product alone overflows.
    assert_eq!(uptime_ticks(&format!("{}.00", max / 100 + 1), 1), None);
    assert_eq!(uptime_ticks(&format!("{}.16", max / 100), 1), None);
    assert_eq!(
        uptime_ticks(&format!("{}.15", max / 100), 1),
        Some(max / 100)
    );
    assert_eq!(uptime_ticks("1.00", libc::c_long::MAX), None);
}

/// Ordinary hundredths convert to ticks, rounding down.
#[test]
fn ib_uptime_arithmetic_converts_ordinary_hundredths() {
    assert_eq!(uptime_ticks("100.00 400.00\n", 100), Some(10_000));
    assert_eq!(uptime_ticks("12.34 1.00\n", 250), Some(3_085));
    assert_eq!(uptime_ticks("0.01\n", 100), Some(1));
    assert_eq!(uptime_ticks("0.01\n", 99), Some(0));
    assert_eq!(uptime_ticks("12.34", 100), Some(1_234));
    assert_eq!(uptime_ticks(" \t12.34\t1.00", 100), Some(1_234));
}

/// Text other than digits, a dot and exactly two digits, and a tick rate
/// below one, refuse.
#[test]
fn malformed_uptime_text_and_tick_rates_refuse() {
    for text in [
        "", "\n", "100", "100.", "100.0", "100.000", ".50", "1x.00", "+1.00", "-1.00", "1.+0",
        "1.-1", "1.0a", "1.a0", "1,00", "١.00", "1.00x", "1.00.5", "1.0٠",
    ] {
        assert_eq!(uptime_ticks(text, 100), None, "{text:?}");
    }
    for hz in [0, -1, libc::c_long::MIN] {
        assert_eq!(uptime_ticks("100.00", hz), None, "{hz}");
    }
}

/// The walk's boot ticks read `uptime` under the fixture's `proc` root at
/// the kernel's tick rate, and refuse malformed, overflowing or missing
/// text.
#[test]
fn boot_ticks_read_the_procfs_uptime() {
    // SAFETY: `sysconf` reads a constant and has no memory arguments.
    let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap();
    let fixture = Fixture::new(4096);
    let proc = &fixture.host.proc;
    assert_eq!(boot_ticks(proc), Some(10_000 * hz / 100));
    fixture.file("proc/uptime", "12.34 1.00\n");
    assert_eq!(boot_ticks(proc), Some(1_234 * hz / 100));
    for malformed in ["12.3 1.00\n", "abc\n", "18446744073709551615.00 0.00\n"] {
        fixture.file("proc/uptime", malformed);
        assert_eq!(boot_ticks(proc), None, "{malformed:?}");
    }
    std::fs::remove_file(proc.join("uptime")).unwrap();
    assert_eq!(boot_ticks(proc), None);
}
