use std::path::Path;

use super::{beside, pure};

/// Each `expected` string matches `str(PurePosixPath(path))`.
#[test]
fn pure_writes_a_path_as_pathlib_does() {
    let rows = [
        ("", "."),
        (".", "."),
        ("/", "/"),
        ("//", "//"),
        ("///", "/"),
        ("a/", "a"),
        ("a/./b", "a/b"),
        ("./a", "a"),
        ("a//b", "a/b"),
        ("/a/../b", "/a/../b"),
        ("//a/b/", "//a/b"),
        ("////a", "/a"),
        ("a/..", "a/.."),
        (".//.", "."),
    ];
    for (path, expected) in rows {
        assert_eq!(pure(path.as_bytes()), Path::new(expected), "{path:?}");
    }
}

/// Each `expected` string matches `str(PurePosixPath(directory) / "injection")`.
#[test]
fn beside_joins_a_name_as_pathlib_does() {
    let rows = [
        ("/", "/injection"),
        ("//", "//injection"),
        (".", "injection"),
        ("ev", "ev/injection"),
        ("/x/ev", "/x/ev/injection"),
    ];
    for (directory, expected) in rows {
        let root = pure(directory.as_bytes());
        assert_eq!(
            beside(&root, "injection"),
            Path::new(expected),
            "{directory:?}"
        );
    }
}
