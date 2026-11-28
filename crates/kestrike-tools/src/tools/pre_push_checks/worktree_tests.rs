use std::io::Cursor;

use super::{letters, unrunnable};
use crate::hook::{Check, ORDER};

#[test]
fn letters_pass_over_each_byte_at_or_above_222_and_draw_across_reads() {
    let mut first = vec![222, 255, 221, 0, 1, 2, 3, 4, 5, 6];
    first.resize(32, 222);
    assert_eq!(&letters(&mut Cursor::new(first)).unwrap(), b"_abcdefg");
    let mut split = vec![222; 29];
    split.extend([0, 1, 2]);
    split.extend([3, 4, 5, 6, 7]);
    split.resize(64, 255);
    assert_eq!(&letters(&mut Cursor::new(split)).unwrap(), b"abcdefgh");
    let mut short = vec![255; 32];
    short.extend([0; 8]);
    assert!(letters(&mut Cursor::new(short)).is_err());
}

#[test]
fn off_linux_the_host_stop_row_alone_is_skipped_with_its_line() {
    for row in ORDER {
        assert_eq!(unrunnable(row.check, true), None, "{:?}", row.check);
        let skipped = unrunnable(row.check, false);
        assert_eq!(
            skipped.is_some(),
            row.check == Check::HostStop,
            "{:?}",
            row.check
        );
    }
    let line = unrunnable(Check::HostStop, false).expect("the row is skipped off Linux");
    assert!(line.contains("run on Linux alone"), "{line}");
    assert!(line.contains("the workspace job runs them"), "{line}");
}
