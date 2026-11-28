use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use crate::python::say;
use crate::text::{Text, escaped, is_space};

fn text(codes: &[u32]) -> Text {
    Text::from_code_points(codes.iter().copied()).expect("each code point is at most U+10FFFF")
}

#[test]
fn repr_quotes_and_escapes_as_python_writes_a_string() {
    #[rustfmt::skip]
    let rows: &[(&str, &[u32], &str)] = &[

        ("repr('')", &[], "''"),
        ("repr('a')", &[0x61], "'a'"),
        ("repr(\"'\")", &[0x27], "\"'\""),
        ("repr('\"')", &[0x22], "'\"'"),
        ("repr('\\'\"')", &[0x27, 0x22], "'\\'\"'"),
        ("repr(\"a'b\")", &[0x61, 0x27, 0x62], "\"a'b\""),
        ("repr('a\"b')", &[0x61, 0x22, 0x62], "'a\"b'"),
        ("repr('\\\\')", &[0x5c], "'\\\\'"),
        ("repr('\\t\\n\\r')", &[0x9, 0xa, 0xd], "'\\t\\n\\r'"),
        ("repr('\\x00\\x1f\\x7f\\x80\\x9f\\xa0\\xad')", &[0x0, 0x1f, 0x7f, 0x80, 0x9f, 0xa0, 0xad], "'\\x00\\x1f\\x7f\\x80\\x9f\\xa0\\xad'"),
        ("repr('\\xe9')", &[0xe9], "'\u{e9}'"),
        ("repr('\\u2028\\u2029')", &[0x2028, 0x2029], "'\\u2028\\u2029'"),
        ("repr('\\u200b')", &[0x200b], "'\\u200b'"),
        ("repr('\\ue000')", &[0xe000], "'\\ue000'"),
        ("repr('\\u0378')", &[0x378], "'\\u0378'"),
        ("repr('\\U0001f600')", &[0x1f600], "'\u{1f600}'"),
        ("repr('\\U000e0001')", &[0xe0001], "'\\U000e0001'"),
        ("repr('\\U000f0000')", &[0xf0000], "'\\U000f0000'"),
        ("repr('\\U0010fffd')", &[0x10fffd], "'\\U0010fffd'"),
        ("repr('\\U0010ffff')", &[0x10ffff], "'\\U0010ffff'"),
        ("repr('\\ud800')", &[0xd800], "'\\ud800'"),
        ("repr('\\udcff')", &[0xdcff], "'\\udcff'"),
        ("repr('\\udc80x')", &[0xdc80, 0x78], "'\\udc80x'"),
        ("repr('\\u3000 \\xa0')", &[0x3000, 0x20, 0xa0], "'\\u3000 \\xa0'"),
        ("repr('\\ufeff')", &[0xfeff], "'\\ufeff'"),
        ("repr('\\u0600')", &[0x600], "'\\u0600'"),
        ("repr('\\u1680')", &[0x1680], "'\\u1680'"),
    ];
    let unassigned = [0x378, 0x10_ffff];
    for &(expression, codes, python) in rows {
        let found = text(codes).repr();
        if codes.iter().any(|code| unassigned.contains(code)) {
            let raw: String = codes
                .iter()
                .map(|&code| char::from_u32(code).expect("a scalar value"))
                .collect();
            assert_eq!(found, format!("'{raw}'"), "{expression}");
            assert_ne!(found, python, "{expression}");
        } else {
            assert_eq!(found, python, "{expression}");
        }
    }
}

#[test]
fn say_writes_one_line_with_controls_and_surrogates_escaped() {
    #[rustfmt::skip]
    let rows: &[(&str, &[u32], &str)] = &[

        ("say('plain')", &[0x70, 0x6c, 0x61, 0x69, 0x6e], "plain\u{a}"),
        ("say('a\\nb')", &[0x61, 0xa, 0x62], "a\\nb\u{a}"),
        ("say('\\r\\t')", &[0xd, 0x9], "\\r\\t\u{a}"),
        ("say('\\x00\\x1b\\x7f\\x85\\x9f')", &[0x0, 0x1b, 0x7f, 0x85, 0x9f], "\\x00\\x1b\\x7f\\x85\\x9f\u{a}"),
        ("say('\\xa0\\u200b')", &[0xa0, 0x200b], "\u{a0}\u{200b}\u{a}"),
        ("say('\\u2028\\u2029')", &[0x2028, 0x2029], "\\u2028\\u2029\u{a}"),
        ("say('\\ud800')", &[0xd800], "\\ud800\u{a}"),
        ("say('\\udcff')", &[0xdcff], "\\udcff\u{a}"),
        ("say('\\'\"\\\\')", &[0x27, 0x22, 0x5c], "'\"\\\u{a}"),
        ("say('\\xe9\\U0001f600')", &[0xe9, 0x1f600], "\u{e9}\u{1f600}\u{a}"),
    ];
    for &(expression, codes, python) in rows {
        let mut out = Vec::new();
        say(&mut out, &text(codes)).expect("a vector takes the line");
        assert_eq!(
            String::from_utf8(out).expect("the line is UTF-8"),
            python,
            "{expression}"
        );
    }
}

#[test]
fn display_writes_a_surrogate_as_a_backslash_escape() {
    #[rustfmt::skip]
    let rows: &[(&str, &[u32], &str)] = &[

        ("sys.stderr.write('\\udcff')", &[0xdcff], "\\udcff"),
        ("sys.stderr.write('a\\ud800b')", &[0x61, 0xd800, 0x62], "a\\ud800b"),
        ("sys.stderr.write('\\n\\xe9')", &[0xa, 0xe9], "\u{a}\u{e9}"),
    ];
    for &(expression, codes, python) in rows {
        assert_eq!(text(codes).to_string(), python, "{expression}");
    }
}

#[test]
fn is_space_holds_for_exactly_the_code_points_python_isspace_takes() {
    let expression = "[hex(c) for c in range(0x110000) if chr(c).isspace()]";
    #[rustfmt::skip]
    let python: &[u32] = &[0x9, 0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000];
    let found: Vec<u32> = (0..=0x10_ffff).filter(|&code| is_space(code)).collect();
    assert_eq!(found, python, "{expression}");
}

#[test]
fn strip_split_and_splitlines_cut_where_python_cuts() {
    #[rustfmt::skip]
    let strip: &[(&str, &str, &str)] = &[
        ("''.strip()", "", ""),
        ("'  '.strip()", "  ", ""),
        ("' a b '.strip()", " a b ", "a b"),
        ("'\\x1c a\\x1fb\\u3000'.strip()", "\u{1c} a\u{1f}b\u{3000}", "a\u{1f}b"),
        ("'\\x85x\\xa0'.strip()", "\u{85}x\u{a0}", "x"),
        ("'a\\x0bb\\x0cc'.strip()", "a\u{b}b\u{c}c", "a\u{b}b\u{c}c"),
        ("'\\u200bx\\u200b'.strip()", "\u{200b}x\u{200b}", "\u{200b}x\u{200b}"),
    ];
    for &(expression, given, python) in strip {
        assert_eq!(Text::from(given).strip(), python, "{expression}");
    }
    #[rustfmt::skip]
    let split: &[(&str, &str, &[&str])] = &[
        ("''.split()", "", &[]),
        ("'  '.split()", "  ", &[]),
        ("' a  b '.split()", " a  b ", &["a", "b"]),
        ("'a\\x1cb\\x1dc\\x1ed\\x1fe'.split()", "a\u{1c}b\u{1d}c\u{1e}d\u{1f}e", &["a", "b", "c", "d", "e"]),
        ("'a\\u2028b\\xa0c\\u200bd'.split()", "a\u{2028}b\u{a0}c\u{200b}d", &["a", "b", "c\u{200b}d"]),
        ("'\\t\\n\\x0b\\x0c\\r x'.split()", "\u{9}\u{a}\u{b}\u{c}\u{d} x", &["x"]),
    ];
    for &(expression, given, python) in split {
        assert_eq!(Text::from(given).split(), python, "{expression}");
    }
    #[rustfmt::skip]
    let lines: &[(&str, &str, &[&str])] = &[
        ("''.splitlines()", "", &[]),
        ("'\\n'.splitlines()", "\u{a}", &[""]),
        ("'a\\n'.splitlines()", "a\u{a}", &["a"]),
        ("'a\\nb'.splitlines()", "a\u{a}b", &["a", "b"]),
        ("'a\\r\\nb'.splitlines()", "a\u{d}\u{a}b", &["a", "b"]),
        ("'a\\r\\rb'.splitlines()", "a\u{d}\u{d}b", &["a", "", "b"]),
        ("'\\r\\n\\n'.splitlines()", "\u{d}\u{a}\u{a}", &["", ""]),
        ("'a\\x0bb\\x0cc\\x1cd\\x1de\\x1ef\\x1fg'.splitlines()", "a\u{b}b\u{c}c\u{1c}d\u{1d}e\u{1e}f\u{1f}g", &["a", "b", "c", "d", "e", "f\u{1f}g"]),
        ("'a\\x85b\\u2028c\\u2029d'.splitlines()", "a\u{85}b\u{2028}c\u{2029}d", &["a", "b", "c", "d"]),
        ("'a\\n\\n'.splitlines()", "a\u{a}\u{a}", &["a", ""]),
    ];
    for &(expression, given, python) in lines {
        assert_eq!(Text::from(given).splitlines(), python, "{expression}");
    }
}

#[test]
fn an_undecodable_byte_reads_as_a_surrogate_and_writes_back_as_the_byte() {
    let bytes = b"a\xff\xc3\xa9\xed\xa0\x80".to_vec();
    let expression = "os.fsdecode(b'a\\xff\\xc3\\xa9\\xed\\xa0\\x80')";
    let python = "'a\\udcff\u{e9}\\udced\\udca0\\udc80'";
    let read = Text::from_os(OsStr::from_bytes(&bytes));
    assert_eq!(read.repr(), python, "{expression}");
    assert_eq!(read.to_os(), Some(OsString::from_vec(bytes)));
    assert_eq!(read.to_str(), None);
    assert_eq!(
        text(&[0xd800]).to_os(),
        None,
        "os.fsencode('\\ud800') raises UnicodeEncodeError"
    );
    for code in [0xdc00, 0xdc7f, 0xdd00, 0xdfff] {
        assert_eq!(
            text(&[code]).to_os(),
            None,
            "os.fsencode(chr({code:#x})) raises UnicodeEncodeError"
        );
    }
    assert_eq!(
        text(&[0xdc80, 0xdcff]).to_os(),
        Some(OsString::from_vec(b"\x80\xff".to_vec())),
        "os.fsencode('\\udc80\\udcff') == b'\\x80\\xff'"
    );
    assert_eq!(Text::from("\u{e9}").to_str(), Some("\u{e9}"));
    assert_eq!(text(&[0x61, 0xdcff]).len(), 2);
}

#[test]
fn texts_order_by_code_point() {
    let expression = "sorted(['\\ue000', '\\ud800', '\\ud7ff', '\\U00010000', 'z', '\\xe9'])";
    #[rustfmt::skip]
    let python: &[u32] = &[0x7a, 0xe9, 0xd7ff, 0xd800, 0xe000, 0x10000];
    let mut found: Vec<Text> = [0xe000, 0xd800, 0xd7ff, 0x10000, 0x7a, 0xe9]
        .iter()
        .map(|&code| text(&[code]))
        .collect();
    found.sort();
    let expected: Vec<Text> = python.iter().map(|&code| text(&[code])).collect();
    assert_eq!(found, expected, "{expression}");
}

#[test]
fn repr_escapes_each_unprintable_range_up_to_its_bounds() {
    let expression = "bad = [c for c in range(0x110000) if unicodedata.category(chr(c)) != 'Cn' and not chr(c).isprintable()]; \
        ranges = [(bad[0], bad[0])]; \
        [ranges.__setitem__(-1, (ranges[-1][0], c)) if c == ranges[-1][1] + 1 else ranges.append((c, c)) for c in bad[1:]]; \
        [(c, chr(c).isprintable()) for c in sorted({c for low, high in ranges for c in (low - 1, low, high, high + 1) if 0 <= c <= 0x10ffff}) if unicodedata.category(chr(c)) != 'Cn']";
    #[rustfmt::skip]
    let python: &[(u32, bool)] = &[(0x0, false), (0x1f, false), (0x20, true), (0x7e, true), (0x7f, false), (0xa0, false), (0xa1, true), (0xac, true), (0xad, false), (0xae, true), (0x600, false), (0x605, false), (0x606, true), (0x61b, true), (0x61c, false), (0x6dc, true), (0x6dd, false), (0x6de, true), (0x70f, false), (0x710, true), (0x8e1, true), (0x8e2, false), (0x8e3, true), (0x167f, true), (0x1680, false), (0x1681, true), (0x180d, true), (0x180e, false), (0x2000, false), (0x200f, false), (0x2010, true), (0x2027, true), (0x2028, false), (0x202f, false), (0x2030, true), (0x205e, true), (0x205f, false), (0x2064, false), (0x2066, false), (0x206f, false), (0x2070, true), (0x3000, false), (0x3001, true), (0xd800, false), (0xf8ff, false), (0xf900, true), (0xfeff, false), (0xfff9, false), (0xfffb, false), (0xfffc, true), (0x110bc, true), (0x110bd, false), (0x110be, true), (0x110cd, false), (0x13430, false), (0x13438, false), (0x1bc9f, true), (0x1bca0, false), (0x1bca3, false), (0x1d172, true), (0x1d173, false), (0x1d17a, false), (0x1d17b, true), (0xe0001, false), (0xe0020, false), (0xe007f, false), (0xf0000, false), (0xffffd, false), (0x100000, false), (0x10fffd, false)];
    for &(code, printable) in python {
        let found = text(&[code]).repr();
        assert_eq!(
            !found.starts_with("'\\"),
            printable,
            "{expression}: U+{code:04X} gives {found}"
        );
    }
}

#[test]
fn splitlines_breaks_at_exactly_the_code_points_python_breaks_at() {
    let expression =
        "[hex(c) for c in range(0x110000) if len(('a' + chr(c) + 'b').splitlines()) == 2]";
    #[rustfmt::skip]
    let python: &[u32] = &[0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029];
    let found: Vec<u32> = (0..=0x10_ffff)
        .filter(|&code| text(&[0x61, code, 0x62]).splitlines().len() == 2)
        .collect();
    assert_eq!(found, python, "{expression}");
}

#[test]
fn a_surrogate_pair_of_code_points_stays_two_surrogates() {
    let expression = "'\\U0001f600' == '\\ud83d\\ude00'";
    let pair = text(&[0xd83d, 0xde00]);
    assert_ne!(pair, Text::from("\u{1f600}"), "{expression} is False");
    assert_eq!(pair.repr(), "'\\ud83d\\ude00'", "repr('\\ud83d\\ude00')");
    let mut grown = Text::from("a");
    assert_eq!(
        grown.push_code_point(0x11_0000),
        None,
        "chr(0x110000) raises ValueError"
    );
    assert_eq!(grown, "a");
}

#[test]
fn push_text_appends_the_code_points_of_another_text() {
    let mut joined = Text::from("a/");
    joined.push_text(&text(&[0xdcff, 0x62]));
    joined.push_text(&Text::from("\u{1f600}"));
    assert_eq!(
        joined.code_points().collect::<Vec<_>>(),
        [0x61, 0x2f, 0xdcff, 0x62, 0x1f600]
    );
    assert_eq!(joined.repr(), "'a/\\udcffb\u{1f600}'");
}

/// `join` puts the separator between each two items alone, takes an empty separator, and copies an item's
/// surrogates as they are.
#[test]
fn join_separates_each_two_items() {
    let odd = Text::from_os(OsStr::from_bytes(b"\xff"));
    let rows: &[(&str, Vec<Text>, &str)] = &[
        (", ", vec![], "''"),
        (", ", vec![Text::from("a")], "'a'"),
        (
            ", ",
            vec![Text::from("a"), Text::from("b"), Text::from("c")],
            "'a, b, c'",
        ),
        ("", vec![Text::from("a"), Text::from("b")], "'ab'"),
        ("/", vec![Text::from("a"), odd], "'a/\\udcff'"),
    ];
    for (separator, items, expected) in rows {
        assert_eq!(Text::join(separator, items).repr(), *expected, "{items:?}");
    }
}

/// `escaped` writes each scalar value as `repr` writes it inside its quotes, apart from a backslash, which it
/// keeps single, so a field of printable code points keeps its bytes.
#[test]
fn escaped_writes_each_scalar_value_as_repr_writes_it_inside_its_quotes() {
    for code in (0..=0x10_ffff).filter_map(char::from_u32) {
        let alone = code.to_string();
        let quoted = Text::from(alone.as_str()).repr();
        let inside = &quoted[1..quoted.len() - 1];
        let expected = if code == '\\' { "\\" } else { inside };
        assert_eq!(escaped(&alone), expected, "U+{:04X}", u32::from(code));
    }
    let printable = "a'b\"c\\'d";
    assert_eq!(escaped(printable), printable);
}
