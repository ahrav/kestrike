use std::io::Cursor;

use super::{Exposure, exposed, foreign_link, letters, planted, writable};

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

/// A link is refused by its owner and its directory's mode together: one that another user than the
/// real user and root owns, in a directory whose group or every user can write. The user's own link
/// and root's pass there, and a link in a directory that only its owner can write passes whoever owns
/// it: root's link beside a root-owned name, as `/tmp` is on macOS, and the same link where root reads
/// as another id, as in a user namespace that maps the real user alone.
#[test]
fn a_link_is_judged_by_its_owner_where_others_can_write_its_directory() {
    let user = 1000;
    for (shape, owner, holder, expected) in [
        (
            "another user's link in a sticky shared directory",
            1001,
            0o041_777,
            true,
        ),
        ("the user's own link there", 1000, 0o041_777, false),
        ("root's link there", 0, 0o041_777, false),
        (
            "another user's link where the group alone can write",
            1001,
            0o041_770,
            true,
        ),
        (
            "root's link in a directory nobody else can write",
            0,
            0o040_755,
            false,
        ),
        (
            "that link where root reads as another id",
            65_534,
            0o040_755,
            false,
        ),
        (
            "another user's link in that user's own directory",
            1001,
            0o040_700,
            false,
        ),
        (
            "root read as another id in a sticky shared directory",
            65_534,
            0o041_777,
            true,
        ),
    ] {
        assert_eq!(planted(owner, holder, user), expected, "{shape}");
    }
    assert!(
        planted(1000, 0o041_777, 0),
        "root trusts no other user's link"
    );
    assert!(!planted(0, 0o041_777, 0));
}

/// The walk reads the path's own name and each name on the way, through each link's target: read for a
/// user other than the one who made them, the test's own links are another user's. A link in a sticky
/// directory that others can write is returned as the path's last name, as a name on the way, after
/// `..`, and behind a link that stands in a private directory; a link in a private directory, an
/// absent name and a link that names itself return none, and so does every path read for the links'
/// owner.
#[test]
fn the_walk_returns_the_first_link_another_user_owns_in_a_shared_directory() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let scratch = crate::paths::tests::Scratch::new("foreign-link");
    let (shared, closed) = (scratch.0.join("shared"), scratch.0.join("closed"));
    for (directory, mode) in [(&shared, 0o1777), (&closed, 0o700)] {
        std::fs::create_dir(directory).expect("the directory is made");
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode))
            .expect("the mode is set");
    }
    std::fs::create_dir_all(shared.join("private/inner")).expect("the directories are made");
    symlink("private", shared.join("own")).expect("the link is made");
    symlink("own", shared.join("chain")).expect("the link is made");
    symlink(shared.join("private"), closed.join("direct")).expect("the link is made");
    symlink(shared.join("own"), closed.join("through")).expect("the link is made");
    symlink("loop", closed.join("loop")).expect("the link is made");
    let me = crate::ownership::real_uid();
    let other = me + 1;
    let rows = [
        (shared.join("own"), Some(shared.join("own"))),
        (shared.join("own/inner"), Some(shared.join("own"))),
        (shared.join("chain"), Some(shared.join("chain"))),
        (
            shared.join("private/../own"),
            Some(shared.join("private/../own")),
        ),
        (closed.join("through/inner"), Some(shared.join("own"))),
        (closed.join("direct/inner"), None),
        (shared.join("private/inner"), None),
        (shared.join("absent/inner"), None),
        (closed.join("loop/inner"), None),
    ];
    for (path, expected) in rows {
        assert_eq!(foreign_link(&path, me), Ok(None), "{}", path.display());
        if me != 0 {
            assert_eq!(
                foreign_link(&path, other),
                Ok(expected),
                "{}",
                path.display()
            );
        }
    }
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700))
        .expect("the mode is set");
    if me != 0 {
        assert_eq!(foreign_link(&shared.join("own"), other), Ok(None));
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
