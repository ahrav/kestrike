use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use super::{INCLUDED, bodies, code, normalized, package_sources, read_text, walk};
use crate::paths::tests::Scratch;
use crate::production_text::blanked;

const GRACE: &str = "crates/kestrike/src/storage/grace.rs";

fn top() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The committed grace source with its one `old` replaced by `new`.
fn planted_grace(old: &str, new: &str) -> String {
    let text = read_text(&top().join(GRACE)).expect("the grace source reads");
    assert_eq!(text.matches(old).count(), 1, "{old:?}");
    text.replacen(old, new, 1)
}

/// The bodies of `fn unpin` in the normalized production text of `source`.
fn unpin_bodies(source: &str) -> Vec<String> {
    bodies(&normalized(&blanked(source).0), &normalized("fn unpin"))
}

/// A body that holds a nested `fn` or `impl` is still the one body its header names.
#[test]
fn a_find_moved_into_a_nested_item_is_refused() {
    let live = "    record.store(INACTIVE, Ordering::Relaxed);\n}";
    let rows = [
        (
            "a nested fn",
            "    fn clear<W: EraWord>(record: &W) {\n        record.store(INACTIVE, Ordering::Release);\n    }\n",
            "{probe::note(Primitive::Store);fn clear<W:EraWord>(record:&W){record.store(INACTIVE,Ordering::Release);}record.store(INACTIVE,Ordering::Relaxed);}",
        ),
        (
            "a nested fn with an array parameter",
            "    fn clear<W: EraWord>(record: &W, _: [u8; 0]) {\n        record.store(INACTIVE, Ordering::Release);\n    }\n",
            "{probe::note(Primitive::Store);fn clear<W:EraWord>(record:&W,_:[u8;0]){record.store(INACTIVE,Ordering::Release);}record.store(INACTIVE,Ordering::Relaxed);}",
        ),
        (
            "a nested impl",
            "    impl Spare {\n        const _: () = record.store(INACTIVE, Ordering::Release);\n    }\n",
            "{probe::note(Primitive::Store);impl Spare{const _:()=record.store(INACTIVE,Ordering::Release);}record.store(INACTIVE,Ordering::Relaxed);}",
        ),
    ];
    for (label, helper, body) in rows {
        let source = planted_grace(
            "    record.store(INACTIVE, Ordering::Release);\n}",
            &format!("{helper}{live}"),
        );
        assert_eq!(unpin_bodies(&source), [body], "{label}");
    }
}

/// A second `fn unpin` in a module beside the first gives the header two bodies.
#[test]
fn a_scope_that_resolves_to_two_bodies_is_refused() {
    let source = planted_grace(
        "    record.store(INACTIVE, Ordering::Release);\n}",
        "    record.store(INACTIVE, Ordering::Release);\n}\n\nmod spare {\n    fn unpin() {}\n}",
    );
    assert_eq!(
        unpin_bodies(&source),
        [
            "{probe::note(Primitive::Store);record.store(INACTIVE,Ordering::Release);}",
            "{}"
        ]
    );
}

/// The include scanner reads one spelling at the start of a line, after any white space.
#[test]
fn the_include_scanner_reads_one_spelling_at_a_line_start() {
    let source = "#[path = \"a.rs\"]\n  #[path = \"b.rs\"]\n#[path  = \"c.rs\"]\n\t#[path = \"d\"]  \n\
                  x #[path = \"e.rs\"]\n#[path = \"\"]\n";
    let found: Vec<&str> = INCLUDED
        .captures_iter(source)
        .map(|found| found.get(1).expect("INCLUDED has group 1").as_str())
        .collect();
    assert_eq!(found, ["a.rs", "b.rs", "d"]);
}

/// A file's text reads `\r\n` and a lone `\r` as `\n`.
#[test]
fn a_text_reads_each_line_ending_as_a_newline() {
    let scratch = Scratch::new("genmc");
    let path = scratch.0.join("crlf.rs");
    fs::write(&path, "a\r\nb\rc\n").expect("the file is written");
    assert_eq!(read_text(&path).expect("the file reads"), "a\nb\nc\n");
}

/// A comment, a nested block comment whole and one that never closes, are one space each, a string
/// after its prefix is `""`, a char literal is `''`, and a lifetime stays; the normal form keeps one
/// space only between two word characters of any script.
#[test]
fn code_writes_each_literal_as_one_token() {
    let source = "fn   f ( a :  u8 ) -> u8 { a + 1 } // tail\n/* c /* nested */ */ let s = b\"str\"; \
                  let r = r#\"raw\"#;\nlet c = 'x'; let l: &'a u8; /* open";
    assert_eq!(
        code(source),
        "fn   f ( a :  u8 ) -> u8 { a + 1 }  \n  let s = b\"\"; let r = \"\";\nlet c = ''; let l: &'a u8;  "
    );
    assert_eq!(
        normalized(source),
        "fn f(a:u8)->u8{a+1}let s=b\"\";let r=\"\";let c='';let l:&'a u8;"
    );
    assert_eq!(
        normalized("let \u{e9} = ( a ) ; let \u{b2} b = \u{e9} \u{b2};"),
        "let \u{e9}=(a);let \u{b2} b=\u{e9} \u{b2};"
    );
}

/// A header counts where no word character or `.` precedes it and no word character of any script
/// follows it; a `;` before the brace leaves no body, a block that never closes gives none, and a
/// header inside an earlier body gives a body of its own.
#[test]
fn a_header_counts_only_at_its_word_edges() {
    let source = "fn f() { a } fn f;\n.fn f { b }\nxfn f { c }\nfn f\u{e9} { d }\nfn f\u{b2} { e }\n\
                  fn f { { nested } }\nfn f(x: [u8; 2]) { g }\nfn f\n{ unclosed\n";
    assert_eq!(bodies(source, "fn f"), ["{ a }", "{ { nested } }"]);
    assert_eq!(
        bodies("fn f() { fn f() { x } }", "fn f"),
        ["{ fn f() { x } }", "{ x }"]
    );
}

/// A package's sources are its regular files and links to one, hidden ones included, build state and
/// a linked directory's contents aside, in component order; then each include a `.rs` file resolves to
/// outside that list, once. An include in a file of another suffix is not read, nor in `.rs`, whose
/// leading `.` makes no suffix. `src/a/c.rs` sorts before `src/a.rs`, its component `a` before `a.rs`.
#[test]
fn the_package_sources_are_its_files_then_their_includes() {
    let scratch = Scratch::new("genmc");
    let package = scratch.0.join("package");
    for directory in ["src/a", "target", "linked"] {
        fs::create_dir_all(package.join(directory)).expect("the directory is made");
    }
    fs::create_dir_all(scratch.0.join("out")).expect("the directory is made");
    let files = [
        (
            "src/b.rs",
            "#[path = \"../../out/x.rs\"]\nmod x;\n#[path = \"a/c.rs\"]\nmod c;\n",
        ),
        ("src/a/c.rs", "#[path = \"../../../out/x.rs\"]\nmod x;\n"),
        ("src/.hidden", ""),
        ("src/d.inc", "#[path = \"../../out/z.rs\"]\nmod z;\n"),
        ("target/t.rs", "#[path = \"../../out/y.rs\"]\nmod y;\n"),
        ("linked/l.rs", ""),
        ("src/a.rs", ""),
        ("src/.rs", "#[path = \"../../out/w.rs\"]\nmod w;\n"),
    ];
    for (path, text) in files {
        fs::write(package.join(path), text).expect("the file is written");
    }
    symlink("../linked", package.join("src/dir")).expect("the link is made");
    symlink("b.rs", package.join("src/link.rs")).expect("the link is made");
    let found: Vec<PathBuf> = package_sources(&package).expect("the package reads");
    let resolved = scratch.0.canonicalize().expect("the scratch root resolves");
    let expected: Vec<PathBuf> = [
        "linked/l.rs",
        "src/.hidden",
        "src/.rs",
        "src/a/c.rs",
        "src/a.rs",
        "src/b.rs",
        "src/d.inc",
        "src/link.rs",
    ]
    .iter()
    .map(|path| package.join(path))
    .chain([resolved.join("out/x.rs")])
    .collect();
    assert_eq!(found, expected);
}

/// A directory the walk may not list is passed over. A process that lists it anyway, as root does,
/// says so and checks nothing.
#[test]
fn a_walk_passes_over_a_directory_it_may_not_list() {
    let scratch = Scratch::new("genmc");
    let closed = scratch.0.join("closed");
    fs::create_dir_all(closed.join("inner")).expect("the directory is made");
    fs::write(scratch.0.join("open.rs"), "").expect("the file is written");
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).expect("the mode is set");
    let listable = fs::read_dir(&closed).is_ok();
    let found = walk(&scratch.0);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).expect("the mode is restored");
    let mut found = found.expect("the walk reads");
    found.sort();
    if listable {
        eprintln!(
            "a_walk_passes_over_a_directory_it_may_not_list: this process lists a mode-000 directory; the listing is checked whole"
        );
        assert_eq!(
            found,
            [
                closed.clone(),
                closed.join("inner"),
                scratch.0.join("open.rs")
            ]
        );
        return;
    }
    assert_eq!(found, [closed, scratch.0.join("open.rs")]);
}

/// A lookup refused permission is an error, not an absent file.
#[test]
fn a_lookup_refused_permission_is_an_error() {
    let scratch = Scratch::new("genmc");
    let closed = scratch.0.join("closed");
    fs::create_dir_all(&closed).expect("the directory is made");
    fs::write(closed.join("f.rs"), "").expect("the file is written");
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).expect("the mode is set");
    let found = super::is_file(&closed.join("f.rs"));
    let searchable = fs::metadata(closed.join("f.rs")).is_ok();
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).expect("the mode is restored");
    if searchable {
        eprintln!(
            "a_lookup_refused_permission_is_an_error: this process searches a mode-000 directory; the lookup is checked"
        );
        assert_eq!(found.ok(), Some(true));
        return;
    }
    let error = found.expect_err("the lookup is refused");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

/// The walk enters a directory, passes over an entry whose type lookup names no file or is refused
/// permission, and returns every other lookup error.
#[test]
fn an_entry_type_lookup_error_stops_the_walk() {
    let scratch = Scratch::new("genmc");
    let directory = fs::symlink_metadata(&scratch.0)
        .expect("the scratch directory reads")
        .file_type();
    let error = |code: i32| Err(std::io::Error::from_raw_os_error(code));
    let found = (
        super::descends(Ok(directory)).ok(),
        super::descends(error(libc::ENOENT)).ok(),
        super::descends(error(libc::EACCES)).ok(),
        super::descends(error(libc::EIO)).map_err(|error| error.raw_os_error()),
    );
    assert_eq!(
        found,
        (Some(true), Some(false), Some(false), Err(Some(libc::EIO)))
    );
}

/// Directories nested past the walk's depth stop it with an error.
#[test]
fn a_walk_stops_past_its_depth() {
    let scratch = Scratch::new("genmc");
    let mut deep = scratch.0.clone();
    for _ in 0..=super::WALK_DEPTH {
        deep.push("d");
    }
    fs::create_dir_all(&deep).expect("the nested directories are made");
    let error = walk(&scratch.0).expect_err("the nesting passes the depth");
    assert!(
        error.to_string().ends_with(&format!(
            "nests directories more than {} deep",
            super::WALK_DEPTH
        )),
        "{error}"
    );
    let shallow = Scratch::new("genmc");
    fs::create_dir_all(shallow.0.join("d/d/d")).expect("the directories are made");
    assert_eq!(walk(&shallow.0).expect("a shallow walk reads").len(), 3);
}

/// An include path that holds a NUL byte names no file, so the package's sources cannot be read.
#[test]
fn an_include_path_with_a_nul_byte_is_an_error() {
    let scratch = Scratch::new("genmc");
    fs::write(
        scratch.0.join("a.rs"),
        "#[path = \"bad\0/../a.rs\"]\nmod a;\n",
    )
    .expect("the source is written");
    let error = package_sources(&scratch.0).expect_err("the include holds a NUL byte");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
