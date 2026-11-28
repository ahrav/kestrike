use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::Path;

use sha1::{Digest, Sha1};
use sha2::Sha256;

use super::tree_difference;
use super::{
    Entries, Entry, Malformed, base_entries, blob_id, carried_blob, named_entries, overlaid,
};
use crate::paths::tests::Scratch;
use crate::python;
use crate::text::Text;

fn bytes(text: &[u8]) -> Text {
    Text::from_os(OsStr::from_bytes(text))
}

fn entry(mode: &str, id: &str) -> Entry {
    Entry {
        mode: Text::from(mode),
        id: Text::from(id),
    }
}

fn entries(rows: &[(&[u8], &str, &str)]) -> Entries {
    rows.iter()
        .map(|(path, mode, id)| (bytes(path), entry(mode, id)))
        .collect()
}

const FILES: [(&str, &[u8], u32); 3] = [
    ("a.txt", b"a\n", 0o644),
    ("bin/run", b"#!/bin/sh\n", 0o755),
    ("src/lib.rs", b"pub fn f() {}\n", 0o644),
];

fn write(root: &Path, path: impl AsRef<Path>, data: &[u8], mode: u32) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().expect("a path below the root")).expect("the parent is made");
    fs::write(&full, data).expect("the file is written");
    fs::set_permissions(&full, fs::Permissions::from_mode(mode)).expect("the mode is set");
}

fn layout(root: &Path) {
    for (path, data, mode) in FILES {
        write(root, path, data, mode);
    }
    symlink("a.txt", root.join("link")).expect("the link is made");
}

fn named(sha256: bool) -> Entries {
    let id = |data: &[u8]| {
        if sha256 {
            blob_id::<Sha256>(data)
        } else {
            blob_id::<Sha1>(data)
        }
    };
    let mut named = Entries::new();
    for (path, data, mode) in FILES {
        let mode = if mode & 0o100 != 0 {
            "100755"
        } else {
            "100644"
        };
        named.insert(Text::from(path), entry(mode, &id(data)));
    }
    named.insert(Text::from("link"), entry("120000", &id(b"a.txt")));
    named
}

fn mkfifo(path: &Path) {
    let made = std::process::Command::new("mkfifo").arg(path).status();
    assert!(made.expect("mkfifo starts").success(), "the FIFO is made");
}

fn relink(root: &Path, path: &str, target: &str) {
    let full = root.join(path);
    fs::remove_file(&full).expect("the entry is removed");
    symlink(target, full).expect("the link is made");
}

fn same(named: Entries) -> Entries {
    named
}

fn submodule(mut named: Entries) -> Entries {
    named.insert(Text::from("sub"), entry("160000", &"0".repeat(40)));
    named
}

type Setup = fn(&Path);
type Named = fn(Entries) -> Entries;

/// The entry a row locks against its own user, restored to mode 0700 once the row has run.
#[derive(Clone, Copy)]
enum Locked {
    Nothing,
    File(&'static str),
    Directory(&'static str),
}

impl Locked {
    /// Whether the locked entry opens for this user, which leaves the row's denial unexercised.
    fn opens(self, root: &Path) -> bool {
        match self {
            Self::Nothing => false,
            Self::File(path) => fs::File::open(root.join(path)).is_ok(),
            Self::Directory(path) => fs::read_dir(root.join(path)).is_ok(),
        }
    }

    fn unlock(self, root: &Path) {
        if let Self::File(path) | Self::Directory(path) = self {
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o700))
                .expect("unlocked");
        }
    }
}

fn raw_link(root: &Path) {
    fs::remove_file(root.join("link")).expect("the entry is removed");
    symlink(OsStr::from_bytes(b"n\xff"), root.join("link")).expect("the link is made");
}

/// The Git blob IDs of the two bytes `n` and FF and of `n` with U+FFFD, from `git hash-object`.
const RAW_TARGET: &str = "dc5c1502f13909c120482ddcdd943d31d9ea86f6";
const LOSSY_TARGET: &str = "552531eaaaeb19f3e6e689470a0ff1eeb93b4348";

fn relinked(id: &'static str) -> impl Fn(Entries) -> Entries {
    move |mut named| {
        named.insert(Text::from("link"), entry("120000", id));
        named
    }
}

#[rustfmt::skip]
const TREE_ROWS: &[(&str, Setup, Named, Option<&[u8]>)] = &[
    ("the same tree", |_| {}, same, None),
    ("a file the commit lacks", |r| write(r, "z.txt", b"z\n", 0o644), same, Some(b"z.txt")),
    ("an empty directory", |r| fs::create_dir(r.join("e")).expect("made"), same, Some(b"e")),
    ("a directory that cannot be listed", |r| {
        write(r, "d/x", b"x\n", 0o644);
        fs::set_permissions(r.join("d"), fs::Permissions::from_mode(0o000)).expect("locked");
    }, |mut n| { n.insert(Text::from("d/x"), entry("100644", &blob_id::<Sha1>(b"x\n"))); n }, Some(b"d")),
    ("a named file the tree lacks, which leaves its directory empty",
     |r| fs::remove_file(r.join("src/lib.rs")).expect("removed"), same, Some(b"src")),
    ("a named file the tree lacks beside others", |r| fs::remove_file(r.join("a.txt")).expect("removed"), same,
     Some(b"a.txt")),
    ("a named link the tree lacks", |r| fs::remove_file(r.join("link")).expect("removed"), same, Some(b"link")),
    ("a link the commit lacks", |r| symlink("a.txt", r.join("x")).expect("made"), same, Some(b"x")),
    ("a file for a named link", |r| {
        fs::remove_file(r.join("link")).expect("removed");
        write(r, "link", b"a.txt", 0o644);
    }, same, Some(b"link")),
    ("a link for a named file", |r| relink(r, "a.txt", "src/lib.rs"), same, Some(b"a.txt")),
    ("a link to a file of the same bytes for a named file", |r| {
        let outside = r.parent().expect("the tree has a parent").join("outside-a.txt");
        fs::write(&outside, b"a\n").expect("written");
        fs::remove_file(r.join("a.txt")).expect("removed");
        symlink(outside, r.join("a.txt")).expect("linked");
    }, same, Some(b"a.txt")),
    ("a named link to a directory", |r| symlink("src", r.join("ld")).expect("linked"), |mut n| {
        n.insert(Text::from("ld"), entry("120000", &blob_id::<Sha1>(b"src")));
        n
    }, None),
    ("a link to a directory the commit lacks", |r| symlink("src", r.join("ld")).expect("linked"), same,
     Some(b"ld")),
    ("an execute bit on a file that cannot be read", |r| {
        fs::set_permissions(r.join("a.txt"), fs::Permissions::from_mode(0o100)).expect("set");
    }, same, Some(b"a.txt")),
    ("a directory for a named file", |r| {
        fs::remove_file(r.join("src/lib.rs")).expect("removed");
        fs::create_dir(r.join("src/lib.rs")).expect("made");
    }, same, Some(b"src/lib.rs")),
    ("an execute bit cleared", |r| {
        fs::set_permissions(r.join("bin/run"), fs::Permissions::from_mode(0o644)).expect("set");
    }, same, Some(b"bin/run")),
    ("an execute bit set", |r| {
        fs::set_permissions(r.join("a.txt"), fs::Permissions::from_mode(0o755)).expect("set");
    }, same, Some(b"a.txt")),
    ("a changed link target", |r| relink(r, "link", "b.txt"), same, Some(b"link")),
    ("CRLF for LF", |r| write(r, "a.txt", b"a\r\n", 0o644), same, Some(b"a.txt")),
    ("changed bytes of one size", |r| write(r, "a.txt", b"b\n", 0o644), same, Some(b"a.txt")),
    ("a FIFO the commit lacks", |r| mkfifo(&r.join("f")), same, Some(b"f")),
    ("a FIFO for a named file", |r| {
        fs::remove_file(r.join("src/lib.rs")).expect("removed");
        mkfifo(&r.join("src/lib.rs"));
    }, same, Some(b"src/lib.rs")),
    ("a name with a byte outside UTF-8", |r| write(r, OsStr::from_bytes(b"n\xff"), b"n\n", 0o644), same,
     Some(b"n\xff")),
    ("code point order before byte order", |r| {
        write(r, OsStr::from_bytes(b"\xf0\x90\x80\x80"), b"1\n", 0o644);
        write(r, OsStr::from_bytes(b"\xff"), b"2\n", 0o644);
    }, same, Some(b"\xff")),
    ("two differences", |r| {
        write(r, "z.txt", b"z\n", 0o644);
        write(r, "b.txt", b"b\n", 0o644);
    }, same, Some(b"b.txt")),
    ("a named mode outside the three", |_| {}, |mut n| {
        let id = n[&Text::from("a.txt")].id.clone();
        n.insert(Text::from("a.txt"), Entry { mode: Text::from("100664"), id });
        n
    }, Some(b"a.txt")),
    ("a named submodule", |r| fs::create_dir(r.join("sub")).expect("made"), submodule, None),
    ("a file below a named submodule", |r| write(r, "sub/x", b"x\n", 0o644), submodule, Some(b"sub/x")),
    ("the worktree's .git", |r| write(r, ".git", b"gitdir: elsewhere\n", 0o644), same, None),
    ("a .git below the top", |r| write(r, "src/.git", b"gitdir: elsewhere\n", 0o644), same, Some(b"src/.git")),
    ("an owner execute bit cleared beside the others", |r| {
        fs::set_permissions(r.join("bin/run"), fs::Permissions::from_mode(0o655)).expect("set");
    }, same, Some(b"bin/run")),
    ("execute bits for the group and the others alone", |r| {
        fs::set_permissions(r.join("a.txt"), fs::Permissions::from_mode(0o654)).expect("set");
    }, same, None),
    ("a link target with a byte outside UTF-8", raw_link, |n| relinked(RAW_TARGET)(n), None),
    ("a link target named by its replacement character", raw_link, |n| relinked(LOSSY_TARGET)(n), Some(b"link")),
    ("a .gitattributes the commit lacks", |r| write(r, ".gitattributes", b"* text\n", 0o644), same,
     Some(b".gitattributes")),
    ("a file in a .git directory at the top", |r| write(r, ".git/x", b"x\n", 0o644), same, Some(b".git/x")),
    ("a named file whose name holds a byte outside UTF-8",
     |r| write(r, OsStr::from_bytes(b"n\xff"), b"n\n", 0o644), |mut n| {
        n.insert(bytes(b"n\xff"), entry("100644", &blob_id::<Sha1>(b"n\n")));
        n
    }, None),
    ("a named submodule that cannot be listed", |r| {
        write(r, "sub/x", b"x\n", 0o644);
        fs::set_permissions(r.join("sub"), fs::Permissions::from_mode(0o000)).expect("locked");
    }, submodule, None),
    ("SHA-256 IDs", |_| {}, |_| named(true), None),
    ("a SHA-256 ID that differs", |r| write(r, "a.txt", b"b\n", 0o644), |_| named(true), Some(b"a.txt")),
];

fn locked(name: &str) -> Locked {
    match name {
        "a directory that cannot be listed" => Locked::Directory("d"),
        "a named submodule that cannot be listed" => Locked::Directory("sub"),
        "an execute bit on a file that cannot be read" => Locked::File("a.txt"),
        _ => Locked::Nothing,
    }
}

/// A named submodule's directory stands outside the comparison even where it cannot be listed, so the
/// entries below it go uncompared.
#[test]
fn tree_difference_names_the_first_differing_path_of_each_kind() {
    for (name, setup, adjust, expected) in TREE_ROWS {
        let scratch = Scratch::new("red-green-tree");
        let root = scratch.0.join("tree");
        DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("the tree is made");
        layout(&root);
        setup(&root);
        let locked = locked(name);
        if locked.opens(&root) {
            eprintln!("{name}: the locked entry opens for this user, so the row is not run");
            locked.unlock(&root);
            continue;
        }
        let found = tree_difference(&root, &adjust(named(false)));
        locked.unlock(&root);
        let found = found.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(found, expected.map(bytes), "{name}");
    }
}

#[test]
fn tree_difference_names_a_top_that_cannot_be_listed_as_a_dot() {
    let scratch = Scratch::new("red-green-tree");
    let absent = tree_difference(&scratch.0.join("absent"), &Entries::new());
    assert_eq!(absent.expect("the top is judged"), Some(Text::from(".")));
    let empty = scratch.0.join("empty");
    fs::create_dir(&empty).expect("made");
    let found = tree_difference(&empty, &Entries::new());
    assert_eq!(found.expect("the top is listed"), None);
}

/// A file the walk lists that cannot be opened for reading is an error with its path.
#[test]
fn a_named_file_that_cannot_be_read_is_an_error_with_its_path() {
    let scratch = Scratch::new("red-green-tree");
    let root = scratch.0.join("tree");
    DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("the tree is made");
    layout(&root);
    fs::set_permissions(root.join("a.txt"), fs::Permissions::from_mode(0o200)).expect("set");
    if fs::File::open(root.join("a.txt")).is_ok() {
        eprintln!("a mode 0200 file opens for this user, so the property is not exercised");
        return;
    }
    let error = tree_difference(&root, &named(false)).expect_err("an unreadable file fails");
    assert_eq!(error.path(), root.join("a.txt"));
    assert_eq!(error.error().kind(), std::io::ErrorKind::PermissionDenied);
}

/// The three SHA-1 examples of FIPS 180-2, Appendix A, and the digest of the empty message.
#[test]
fn sha1_gives_the_standard_vectors() {
    let million = vec![b'a'; 1_000_000];
    let rows: [(&[u8], &str); 4] = [
        (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        (&million, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
    ];
    for (data, digest) in rows {
        assert_eq!(
            python::hex(&Sha1::digest(data)),
            digest,
            "{} bytes",
            data.len()
        );
    }
}

/// Each ID was recorded once with Git 2.50.1's `git hash-object --no-filters`; the link target is hashed as
/// its raw bytes, as Git stores a link.
#[test]
fn blob_id_gives_the_ids_git_hash_object_writes() {
    let crlf = b"a\r\nb\r\n".repeat(20);
    let rows: [(&str, &[u8], &str); 3] = [
        (
            "the empty blob",
            b"",
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
        ),
        (
            "120 bytes of CRLF lines",
            &crlf,
            "a5cf05ecdc06b110632b754f7024528b61d7120b",
        ),
        (
            "a link's target",
            b"src/lib.rs",
            "c7ca8e348707c577d55d8144a801b5108f6c26fd",
        ),
    ];
    for (name, data, id) in rows {
        assert_eq!(blob_id::<Sha1>(data), id, "{name}");
    }
}

/// `git ls-tree -r -z --full-tree HEAD` of a scratch repository of object format SHA-256, recorded once
/// with Git 2.50.1; the tree that commit names compares equal to it.
#[test]
fn a_sha256_repository_names_the_tree_its_files_hash_to() {
    const LISTED: &[u8] =
        b"100644 blob f8625e43f9e04f24291f77cdbe4c71b3c2a3b0003f60419b3ed06a058d766c8b\ta.txt\0\
        100755 blob 1249034e3cf9007362d695b09b1fbdb4c578903bf10b665749b94743f8177ce1\tbin/run\0\
        120000 blob 0efe919905516cae9a49c9b6d2728c6788da5c9133469312b2b5c053e78d1a6b\tlink\0";
    let scratch = Scratch::new("red-green-tree");
    let root = scratch.0.join("tree");
    DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("the tree is made");
    write(&root, "a.txt", b"a\n", 0o644);
    write(&root, "bin/run", b"#!/bin/sh\n", 0o755);
    symlink("a.txt", root.join("link")).expect("the link is made");
    let named = named_entries(LISTED).expect("the listing reads");
    assert_eq!(
        tree_difference(&root, &named).expect("the tree reads"),
        None
    );
    write(&root, "a.txt", b"a\r\n", 0o644);
    assert_eq!(
        tree_difference(&root, &named).expect("the tree reads"),
        Some(Text::from("a.txt"))
    );
}

#[test]
fn named_entries_maps_each_path_to_its_mode_and_id() {
    let id = |digit: &str| digit.repeat(40);
    let rows: Vec<(&str, Vec<u8>, Entries)> = vec![
        (
            "two records",
            [
                b"100644 blob ",
                id("1").as_bytes(),
                b"\ta.txt\x00100755 blob ",
                id("2").as_bytes(),
                b"\tbin/run\0",
            ]
            .concat(),
            entries(&[
                (b"a.txt", "100644", &id("1")),
                (b"bin/run", "100755", &id("2")),
            ]),
        ),
        (
            "a path holding a tab",
            [b"100644 blob ", id("3").as_bytes(), b"\ta\tb\0"].concat(),
            entries(&[(b"a\tb", "100644", &id("3"))]),
        ),
        (
            "a path with a byte outside UTF-8",
            [b"100644 blob ", id("4").as_bytes(), b"\tn\xff\0"].concat(),
            entries(&[(b"n\xff", "100644", &id("4"))]),
        ),
        (
            "a link and a submodule",
            [
                b"120000 blob ",
                id("5").as_bytes(),
                b"\tl\x00160000 commit ",
                id("6").as_bytes(),
                b"\ts\0",
            ]
            .concat(),
            entries(&[(b"l", "120000", &id("5")), (b"s", "160000", &id("6"))]),
        ),
        ("no output", Vec::new(), Entries::new()),
        (
            "a record without a final NUL",
            [b"100644 blob ", id("7").as_bytes(), b"\tlast"].concat(),
            entries(&[(b"last", "100644", &id("7"))]),
        ),
        (
            "two records for one path",
            [
                b"100644 blob ",
                id("8").as_bytes(),
                b"\tp\x00100755 blob ",
                id("9").as_bytes(),
                b"\tp\0",
            ]
            .concat(),
            entries(&[(b"p", "100755", &id("9"))]),
        ),
    ];
    for (name, stdout, expected) in rows {
        assert_eq!(named_entries(&stdout), Ok(expected), "{name}");
    }
}

/// A record of mode 160000 reads as a submodule whatever its type and ID, so the file at its path stands
/// outside the comparison; the same record with the file's mode compares the file.
#[test]
fn a_record_with_a_submodule_mode_takes_its_path_out_of_the_comparison() {
    let scratch = Scratch::new("red-green-tree");
    let root = scratch.0.join("tree");
    DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("the tree is made");
    write(&root, "a.txt", b"changed\n", 0o644);
    let listed = |mode: &str| {
        let record = format!("{mode} blob {}\ta.txt\0", blob_id::<Sha1>(b"a\n"));
        named_entries(record.as_bytes()).expect("the record has three fields")
    };
    let found = |mode: &str| tree_difference(&root, &listed(mode)).expect("the tree reads");
    assert_eq!(found("160000"), None);
    assert_eq!(found("100644"), Some(Text::from("a.txt")));
}

/// A record without a tab, with fewer than three fields before it or with more is malformed.
#[test]
fn a_record_of_another_form_is_malformed() {
    for record in [
        &b"100644 blob abc"[..],
        b"100644 abc\tp",
        b"100644 blob abc extra\tp",
    ] {
        let stdout = [
            b"100644 blob ",
            "1".repeat(40).as_bytes(),
            b"\tok\0",
            record,
            b"\0",
        ]
        .concat();
        assert_eq!(named_entries(&stdout), Err(Malformed(record.to_vec())));
    }
}

const HEAD: &str = "abcdef0123456789abcdef0123456789abcdef01";

#[test]
fn carried_blob_takes_one_regular_file_at_the_path() {
    let refused = |path: &str| {
        Err(format!(
            "the head abcdef012345 holds no regular file {path}"
        ))
    };
    type Row<'a> = (&'a str, &'a [u8], Vec<u8>, Result<String, String>);
    let rows: Vec<Row> = vec![
        (
            "a regular file",
            b"t.rs",
            [b"100644 blob ", "a".repeat(40).as_bytes(), b"\tt.rs\0"].concat(),
            Ok("a".repeat(40)),
        ),
        (
            "an executable file",
            b"t.rs",
            [b"100755 blob ", "b".repeat(40).as_bytes(), b"\tt.rs\0"].concat(),
            Ok("b".repeat(40)),
        ),
        (
            "a link",
            b"t.rs",
            [b"120000 blob ", "c".repeat(40).as_bytes(), b"\tt.rs\0"].concat(),
            refused("'t.rs'"),
        ),
        (
            "a directory",
            b"d",
            [b"040000 tree ", "d".repeat(40).as_bytes(), b"\td\0"].concat(),
            refused("'d'"),
        ),
        ("no record", b"t.rs", Vec::new(), refused("'t.rs'")),
        (
            "another path",
            b"t.rs",
            [b"100644 blob ", "e".repeat(40).as_bytes(), b"\tu.rs\0"].concat(),
            refused("'t.rs'"),
        ),
        (
            "two records",
            b"t.rs",
            [
                b"100644 blob ",
                "f".repeat(40).as_bytes(),
                b"\tt.rs\x00100644 blob ",
                "0".repeat(40).as_bytes(),
                b"\tt.rs\0",
            ]
            .concat(),
            refused("'t.rs'"),
        ),
        (
            "a path with a byte outside UTF-8",
            b"n\xff",
            [b"100644 blob ", "1".repeat(40).as_bytes(), b"\tn\xff\0"].concat(),
            Ok("1".repeat(40)),
        ),
        (
            "two fields",
            b"t.rs",
            [b"100644 ", "2".repeat(40).as_bytes(), b"\tt.rs\0"].concat(),
            refused("'t.rs'"),
        ),
    ];
    for (name, path, stdout, expected) in rows {
        let found = carried_blob(HEAD, &bytes(path), &stdout);
        let found = found
            .map(|blob| blob.to_string())
            .map_err(|reason| reason.to_string());
        assert_eq!(found, expected, "{name}");
    }
}

#[test]
fn overlaid_holds_for_a_carried_path_and_the_paths_above_and_below_it() {
    let rows: [(&str, &str, &[&str], bool); 7] = [
        ("a carried path", "t/a.rs", &["t/a.rs"], true),
        ("a path below a carried path", "t/a.rs/x", &["t/a.rs"], true),
        (
            "a file a carried path needs as a directory",
            "t",
            &["t/a.rs"],
            true,
        ),
        ("a sibling", "t/b.rs", &["t/a.rs"], false),
        (
            "a shared prefix without a slash",
            "t/a.rs.bak",
            &["t/a.rs"],
            false,
        ),
        (
            "a carried path's prefix without a slash",
            "t/a",
            &["t/a.rs"],
            false,
        ),
        ("no carried path", "t", &[], false),
    ];
    for (name, path, carry, expected) in rows {
        let carry: Vec<Text> = carry.iter().map(|path| Text::from(*path)).collect();
        assert_eq!(overlaid(&Text::from(path), &carry), expected, "{name}");
    }
}

#[test]
fn base_entries_lay_the_carried_paths_over_the_base() {
    let id = |digit: &str| digit.repeat(40);
    let base = entries(&[
        (b"a", "100644", &id("1")),
        (b"t", "100644", &id("2")),
        (b"t2/x", "100644", &id("3")),
        (b"u/v", "100755", &id("4")),
    ]);
    let head = entries(&[
        (b"a", "100644", &id("5")),
        (b"t/x.rs", "100755", &id("6")),
        (b"u/v/w.rs", "100644", &id("7")),
        (b"t2/x", "100644", &id("8")),
    ]);
    let rows: [(&str, &[&str], Entries); 4] = [
        (
            "one carried path that replaces a base file",
            &["t/x.rs"],
            entries(&[
                (b"a", "100644", &id("1")),
                (b"t2/x", "100644", &id("3")),
                (b"u/v", "100755", &id("4")),
                (b"t/x.rs", "100755", &id("6")),
            ]),
        ),
        (
            "a carried path below a base file",
            &["u/v/w.rs"],
            entries(&[
                (b"a", "100644", &id("1")),
                (b"t", "100644", &id("2")),
                (b"t2/x", "100644", &id("3")),
                (b"u/v/w.rs", "100644", &id("7")),
            ]),
        ),
        (
            "a carried path that replaces a base path",
            &["t2/x"],
            entries(&[
                (b"a", "100644", &id("1")),
                (b"t", "100644", &id("2")),
                (b"u/v", "100755", &id("4")),
                (b"t2/x", "100644", &id("8")),
            ]),
        ),
        (
            "a carried path twice",
            &["t/x.rs", "t/x.rs"],
            entries(&[
                (b"a", "100644", &id("1")),
                (b"t2/x", "100644", &id("3")),
                (b"u/v", "100755", &id("4")),
                (b"t/x.rs", "100755", &id("6")),
            ]),
        ),
    ];
    for (name, carry, expected) in rows {
        let carry: Vec<Text> = carry.iter().map(|path| Text::from(*path)).collect();
        assert_eq!(base_entries(&base, &head, &carry), Ok(expected), "{name}");
    }
    let missing = [Text::from("absent.rs")];
    assert_eq!(
        base_entries(&base, &head, &missing),
        Err(Text::from("absent.rs"))
    );
}
