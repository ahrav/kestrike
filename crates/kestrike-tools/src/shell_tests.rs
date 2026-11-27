use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use crate::shell::{Error, split};
use crate::text::Text;

type Row<'a> = (&'a str, &'a str, Result<&'a [&'a str], (Error, &'a str)>);

#[test]
fn split_follows_the_posix_shell_rules_and_names_each_error() {
    #[rustfmt::skip]
    let rows: &[Row] = &[
        ("shlex.split('')", "", Ok(&[])),
        ("shlex.split('  ')", "  ", Ok(&[])),
        ("shlex.split('a b')", "a b", Ok(&["a", "b"])),
        ("shlex.split(' a\\tb\\rc\\nd ')", " a\u{9}b\u{d}c\u{a}d ", Ok(&["a", "b", "c", "d"])),
        ("shlex.split('a\\x0bb')", "a\u{b}b", Ok(&["a\u{b}b"])),
        ("shlex.split(\"'a b'\")", "'a b'", Ok(&["a b"])),
        ("shlex.split(\"'a\\\\b'\")", "'a\\b'", Ok(&["a\\b"])),
        ("shlex.split('\"a b\"')", "\"a b\"", Ok(&["a b"])),
        ("shlex.split('\"a\\\\\"b\"')", "\"a\\\"b\"", Ok(&["a\"b"])),
        ("shlex.split('\"a\\\\\\\\b\"')", "\"a\\\\b\"", Ok(&["a\\b"])),
        ("shlex.split('\"a\\\\nb\"')", "\"a\\nb\"", Ok(&["a\\nb"])),
        ("shlex.split('\"a\\\\$b\"')", "\"a\\$b\"", Ok(&["a\\$b"])),
        ("shlex.split('a\\\\ b')", "a\\ b", Ok(&["a b"])),
        ("shlex.split('a\\\\\\\\b')", "a\\\\b", Ok(&["a\\b"])),
        ("shlex.split(\"\\\\'\")", "\\'", Ok(&["'"])),
        ("shlex.split('a\\\\\\nb')", "a\\\u{a}b", Ok(&["a\u{a}b"])),
        ("shlex.split(\"''\")", "''", Ok(&[""])),
        ("shlex.split('\"\"')", "\"\"", Ok(&[""])),
        ("shlex.split(\"a''\")", "a''", Ok(&["a"])),
        ("shlex.split(\"'' b\")", "'' b", Ok(&["", "b"])),
        ("shlex.split('a\\'b\\'\"c\"d')", "a'b'\"c\"d", Ok(&["abcd"])),
        ("shlex.split('\\'\"\\'')", "'\"'", Ok(&["\""])),
        ("shlex.split('\"\\'\"')", "\"'\"", Ok(&["'"])),
        ("shlex.split('x # y')", "x # y", Ok(&["x", "#", "y"])),
        ("shlex.split('\\xe9 \\u3000')", "\u{e9} \u{3000}", Ok(&["\u{e9}", "\u{3000}"])),
        ("shlex.split(\"--test-threads=1 'a  b'\")", "--test-threads=1 'a  b'", Ok(&["--test-threads=1", "a  b"])),
        ("shlex.split(\"'open\")", "'open", Err((Error::UnclosedQuotation, "No closing quotation"))),
        ("shlex.split('\"open')", "\"open", Err((Error::UnclosedQuotation, "No closing quotation"))),
        ("shlex.split('a\\\\')", "a\\", Err((Error::TrailingBackslash, "No escaped character"))),
        ("shlex.split('\"a\\\\')", "\"a\\", Err((Error::TrailingBackslash, "No escaped character"))),
        ("shlex.split(\"'a\\\\\")", "'a\\", Err((Error::UnclosedQuotation, "No closing quotation"))),
    ];
    for &(expression, given, python) in rows {
        let found = split(&Text::from(given));
        match python {
            Ok(words) => assert_eq!(
                found,
                Ok(words.iter().map(|&word| Text::from(word)).collect()),
                "{expression}"
            ),
            Err((error, message)) => assert_eq!(
                found,
                Err(error),
                "{expression} raises ValueError({message:?})"
            ),
        }
    }
}

#[test]
fn an_undecodable_byte_stays_in_its_word() {
    let expression = "shlex.split(os.fsdecode(b'a\\xff \"b c\"'))";
    let python = ["'a\\udcff'", "'b c'"];
    let found =
        split(&Text::from_os(OsStr::from_bytes(b"a\xff \"b c\""))).expect("the text splits");
    let found: Vec<String> = found.iter().map(Text::repr).collect();
    assert_eq!(found, python, "{expression}");
}
