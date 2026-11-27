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

/// A comment, a nested block comment whole and one that never closes, are one space each, a string
/// after its prefix is `""`, a char literal is `''`, and a lifetime stays; the normal form keeps one
/// space only between two word characters.
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
}

/// A header counts where no word character or `.` precedes it and no word character of any script
/// follows it; a `;` before the brace leaves no body, and a block that never closes gives none.
#[test]
fn a_header_counts_only_at_its_word_edges() {
    let source = "fn f() { a } fn f;\n.fn f { b }\nxfn f { c }\nfn f\u{e9} { d }\nfn f\u{b2} { e }\n\
                  fn f { { nested } }\nfn f(x: [u8; 2]) { g }\nfn f\n{ unclosed\n";
    assert_eq!(bodies(source, "fn f"), ["{ a }", "{ { nested } }"]);
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

/// A package's sources are its regular files and links to one, hidden ones included, build state and
/// a linked directory's contents aside, in component order; then each include they resolve to outside
/// that list, once.
#[test]
fn the_package_sources_are_its_files_then_their_includes() {
    let scratch = Scratch::new("genmc");
    let package = scratch.0.join("package");
    for directory in ["src/a", "target", "linked", "out"] {
        fs::create_dir_all(package.join(directory)).expect("the directory is made");
    }
    fs::create_dir_all(scratch.0.join("out")).expect("the directory is made");
    fs::write(
        package.join("src/b.rs"),
        "#[path = \"../../out/x.rs\"]\nmod x;\n#[path = \"a/c.rs\"]\nmod c;\n",
    )
    .expect("the source is written");
    fs::write(
        package.join("src/a/c.rs"),
        "#[path = \"../../../out/x.rs\"]\nmod x;\n",
    )
    .expect("the source is written");
    fs::write(package.join("src/.hidden"), "").expect("the file is written");
    fs::write(
        package.join("target/t.rs"),
        "#[path = \"../../out/y.rs\"]\nmod y;\n",
    )
    .expect("the file is written");
    fs::write(package.join("linked/l.rs"), "").expect("the file is written");
    symlink("../linked", package.join("src/dir")).expect("the link is made");
    symlink("b.rs", package.join("src/link.rs")).expect("the link is made");
    let found: Vec<PathBuf> = package_sources(&package).expect("the package reads");
    let resolved = scratch.0.canonicalize().expect("the scratch root resolves");
    let expected: Vec<PathBuf> = [
        "linked/l.rs",
        "src/.hidden",
        "src/a/c.rs",
        "src/b.rs",
        "src/link.rs",
    ]
    .iter()
    .map(|path| package.join(path))
    .chain([resolved.join("out/x.rs")])
    .collect();
    assert_eq!(found, expected);
}

/// A directory the walk may not list is passed over.
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
    if listable {
        return;
    }
    let mut found = found.expect("the walk passes over the closed directory");
    found.sort();
    assert_eq!(found, [closed, scratch.0.join("open.rs")]);
}
