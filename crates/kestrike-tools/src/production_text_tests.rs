use crate::production_text::{Closer, analyzed, blanked, closing, item_end, spliced};

#[rustfmt::skip]
const PRODUCTION_ROWS: &[(&str, &str, &str)] = &[
    ("an empty text", "", ""),
    ("a text without a cfg attribute", "fn live() {}\n#[test]\nfn probe() {}\n", "fn live() {}\n#[test]\nfn probe() {}\n"),
    ("an unclosed block comment", "fn live() {}\n/* #[cfg(test)]\nfn probe() {}\n", "fn live() {}\n/* #[cfg(test)]\nfn probe() {}\n"),
    ("a test item", "fn live() {}\n#[cfg(test)]\n#[inline]\nfn probe() { let x = \"}\"; }\nfn after() {}\n", "fn live() {}\n            \n         \n                           \nfn after() {}\n"),
    ("a test module after an attribute", "#[allow(dead_code)]\n#[cfg(all(test, loom))]\nmod model {\n    fn a() {}\n}\nfn b() {}\n", "                   \n                       \n           \n             \n \nfn b() {}\n"),
    ("a comment holds the attribute", "// #[cfg(test)]\nfn live() {}\n", "// #[cfg(test)]\nfn live() {}\n"),
    ("test with a word outside ASCII after it", "#[cfg(all(test\u{b2}))]\nfn probe() {}\n", "#[cfg(all(test\u{b2}))]\nfn probe() {}\n"),
    ("test with a mark outside ASCII after it", "#[cfg(all(test\u{301}))]\nfn probe() {}\n", "                   \n             \n"),
    ("an item keyword with a word outside ASCII after it", "fn f(n: u8) -> u8 {\n    match n {\n        #[cfg(test)]\n        type\u{b2} => 1, _ => 2,\n    }\n}\n", "fn f(n: u8) -> u8 {\n    match n {\n                    \n                     _ => 2,\n    }\n}\n"),
    ("an item keyword with a mark outside ASCII after it", "fn f(n: u8) -> u8 {\n    match n {\n        #[cfg(test)]\n        type\u{301} => 1, _ => 2,\n    }\n}\n", "fn f(n: u8) -> u8 {\n    match n {\n                    \n                            \n    }\n}\n"),
    ("a test-only element without an end", "fn f() {}\n#[cfg(test)]\nconst A: u8 = 1\n", "fn f() {}\n#[cfg(test)]\nconst A: u8 = 1\n"),
];

#[rustfmt::skip]
const CUT_ROWS: &[(&str, &str, &[usize])] = &[
    ("a generic parameter", "fn extra<A, #[cfg(test)] B>(a: A) -> A {\n    a\n}\n", &[12]),
    ("a statement keyword with a mark outside ASCII after it", "m!(a, #[cfg(test)] let\u{301} x = 1; b);\n", &[]),
    ("a statement keyword with a word outside ASCII after it", "m!(a, #[cfg(test)] let\u{b2} x = 1; b);\n", &[6]),
    ("a union", "m!(#[cfg(test)] union U { a: u8 });\n", &[]),
    ("a union named by a letter outside ASCII", "m!(#[cfg(test)] union \u{e9} { a: u8 });\n", &[3]),
    ("union as", "m!(#[cfg(test)] union as u8);\n", &[3]),
    ("union as with a mark outside ASCII after it", "m!(#[cfg(test)] union as\u{301} { a: u8 });\n", &[3]),
    ("union as with a word outside ASCII after it", "m!(#[cfg(test)] union as\u{b2} { a: u8 });\n", &[]),
    ("union if", "m!(#[cfg(test)] union if x {});\n", &[3]),
    ("a static", "m!(#[cfg(test)] static S: u8 = 0;);\n", &[]),
    ("static move", "m!(#[cfg(test)] static move || 1);\n", &[3]),
    ("static move with a word outside ASCII after it", "m!(#[cfg(test)] static move\u{b2}: u8 = 0;);\n", &[]),
    ("static move with a mark outside ASCII after it", "m!(#[cfg(test)] static move\u{301}: u8 = 0;);\n", &[3]),
    ("macro_rules after a word outside ASCII", "x\u{b2}macro_rules! m { #[cfg(test)] a, b }\n", &[]),
    ("macro_rules after a mark outside ASCII", "x\u{301}macro_rules! m { #[cfg(test)] a, b }\n", &[20]),
    ("a static mut", "m!(#[cfg(test)] static mut S: u8 = 0;);\n", &[]),
    ("a static named by m", "m!(#[cfg(test)] static mx: u8 = 0;);\n", &[]),
    ("a union named i32", "m!(#[cfg(test)] union i32 { a: u8 });\n", &[]),
    ("a union named ifx", "m!(#[cfg(test)] union ifx { a: u8 });\n", &[]),
    ("a union named ab", "m!(#[cfg(test)] union ab { a: u8 });\n", &[]),
    ("a test-only element without an end", "fn f() {}\n#[cfg(test)]\nconst A: u8 = 1\n", &[]),
    ("a test-only element inside a test-only module", "#[cfg(test)]\nmod probes {\n    fn extra<A, #[cfg(test)] B>(a: A) -> A {\n        a\n    }\n}\n", &[]),
];

#[test]
fn each_row_reads_its_recorded_production_text() {
    for &(label, source, production) in PRODUCTION_ROWS {
        assert_eq!(
            analyzed(source).production(),
            production,
            "{label}: {source:?}"
        );
    }
}

#[test]
fn each_row_reads_its_recorded_cut() {
    for &(label, source, cut) in CUT_ROWS {
        assert_eq!(analyzed(source).cut(), cut, "{label}: {source:?}");
    }
}

/// The scanned text of every row is the production text with comments and literals blanked, so a block
/// comment that never closes blanks the rest of the text.
#[test]
fn the_scanned_text_is_the_code_of_the_production_text() {
    for &(label, source, _) in PRODUCTION_ROWS {
        let analysis = analyzed(source);
        assert_eq!(
            analysis.scanned(),
            crate::rust_text::code(analysis.production()),
            "{label}"
        );
    }
    let (production, scanned) = blanked("fn live() {}\n/* #[cfg(test)]\nfn probe() {}\n");
    assert_eq!(production, "fn live() {}\n/* #[cfg(test)]\nfn probe() {}\n");
    assert_eq!(scanned, "fn live() {}\n               \n             \n");
}

const NBSP: &str = "\u{a0}";

/// The windows of the test-only reading span code points of the source: 8 before an attribute's bracket
/// and 80 before a macro's bracket. A no-break space is white space of two bytes, and a `é` in a comment is
/// one code point of the source and two spaces of the scanned text.
#[test]
fn a_window_of_the_test_only_reading_spans_its_count_of_code_points() {
    let field = |spaces: usize| {
        format!(
            "fn f() {{\n    S {{ #{}[inline] #[cfg(test)] const a, b }}\n}}\n",
            NBSP.repeat(spaces)
        )
    };
    let blanked_to = |text: &str| {
        analyzed(text)
            .production()
            .trim_end_matches(['}', '\n', ' '])
            .len()
    };
    assert!(
        analyzed(&field(7))
            .production()
            .ends_with("S {                                                 }\n}\n"),
        "the hash 8 code points back reads the element as an item, which runs to the brace"
    );
    assert!(
        analyzed(&field(8)).production().ends_with(" b }\n}\n"),
        "the hash 9 code points back reads the element as a field, which ends at its comma"
    );
    assert!(blanked_to(&field(7)) < blanked_to(&field(8)));
    let invocation = |spaces: usize| format!("m!{}(#[cfg(test)] a, b);\n", NBSP.repeat(spaces));
    assert_eq!(
        analyzed(&invocation(78)).cut(),
        [159],
        "the bang 80 code points back"
    );
    assert_eq!(
        analyzed(&invocation(79)).cut(),
        [] as [usize; 0],
        "the bang 81 code points back"
    );
    let commented = |count: usize| "\u{e9}".repeat(count);
    let field = |count: usize| {
        format!(
            "fn f() {{\n    S {{ #/*{}*/[inline] #[cfg(test)] const a, b }}\n}}\n",
            commented(count)
        )
    };
    assert!(
        analyzed(&field(3)).production().ends_with("        }\n}\n"),
        "a comment's code points count once each"
    );
    assert!(analyzed(&field(4)).production().ends_with("      b }\n}\n"));
    let invocation = |count: usize| format!("m!/*{}*/(#[cfg(test)] a, b);\n", commented(count));
    assert_eq!(analyzed(&invocation(74)).cut(), [155]);
    assert_eq!(analyzed(&invocation(75)).cut(), [] as [usize; 0]);
}

#[test]
fn closing_counts_braces_from_its_start() {
    assert_eq!(closing("{ { } }x", 0), Some(7));
    assert_eq!(closing("{ {", 0), None);
    assert_eq!(
        closing("x{}", 0),
        Some(1),
        "a start that holds no brace closes at once"
    );
    assert_eq!(
        closing("\u{e9}{}", 0),
        Some(2),
        "just past the character at the start"
    );
    assert_eq!(
        closing("}{}", 0),
        Some(2),
        "a closing brace first takes the count below zero, and the next opening brace returns it to zero"
    );
}

#[test]
fn item_end_reads_an_item_past_the_commas_of_its_generics() {
    let text = "fn f<A, B>() {} x";
    assert_eq!(item_end(text, 0, Closer::Item), Some(15));
    assert_eq!(item_end(text, 0, Closer::Comma), Some(7));
    assert_eq!(item_end("A, B> x", 0, Closer::Angle), Some(2));
    assert_eq!(item_end("A> x", 0, Closer::Angle), Some(1));
    assert_eq!(
        item_end("a -> b, c", 0, Closer::Angle),
        Some(7),
        "`->` opens no list"
    );
    assert_eq!(item_end("a| x", 0, Closer::Pipe), Some(1));
    assert_eq!(item_end("a", 0, Closer::Comma), None);
}

#[test]
fn spliced_blanks_overlapping_spans_once_and_keeps_newlines() {
    assert_eq!(
        spliced("abcdef\ngh", &[(4, 8), (1, 3), (2, 5)]),
        "a     \n h"
    );
    assert_eq!(spliced("\u{e9}x", &[(0, 2)]), "  x");
}
