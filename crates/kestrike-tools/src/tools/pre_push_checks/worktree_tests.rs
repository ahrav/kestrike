use std::io::Cursor;

use super::letters;

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
