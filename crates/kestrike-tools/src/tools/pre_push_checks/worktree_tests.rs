use std::io::Cursor;

use super::{Exposure, exposed, letters, writable};

/// A directory another user than the real user and root owns is refused whatever its mode, the sticky
/// bit included; a directory the real user or root owns is refused with a group or other write bit and no
/// sticky bit, and passes with the sticky bit or with neither write bit. A directory above it is judged
/// by those bits alone.
#[test]
fn a_scratch_parent_is_judged_by_its_owner_and_then_its_write_and_sticky_bits() {
    let user = 1000;
    for (owner, mode, expected) in [
        (1000, 0o040_700, None),
        (1000, 0o040_755, None),
        (1000, 0o040_750, None),
        (1000, 0o041_777, None),
        (1000, 0o041_770, None),
        (1000, 0o040_777, Some(Exposure::Writable)),
        (1000, 0o040_770, Some(Exposure::Writable)),
        (1000, 0o040_702, Some(Exposure::Writable)),
        (0, 0o041_777, None),
        (0, 0o040_755, None),
        (0, 0o040_777, Some(Exposure::Writable)),
        (0, 0o040_775, Some(Exposure::Writable)),
        (1001, 0o040_700, Some(Exposure::Owned)),
        (1001, 0o040_755, Some(Exposure::Owned)),
        (1001, 0o041_777, Some(Exposure::Owned)),
        (1001, 0o040_777, Some(Exposure::Owned)),
        (65_534, 0o041_777, Some(Exposure::Owned)),
    ] {
        assert_eq!(exposed(owner, mode, user), expected, "{owner} {mode:o}");
    }
    assert_eq!(exposed(1000, 0o040_700, 0), Some(Exposure::Owned));
    assert_eq!(exposed(0, 0o041_777, 0), None);
    for (mode, expected) in [
        (0o040_755, false),
        (0o040_555, false),
        (0o041_777, false),
        (0o041_775, false),
        (0o040_777, true),
        (0o040_775, true),
        (0o040_757, true),
    ] {
        assert_eq!(writable(mode), expected, "{mode:o}");
    }
}

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
