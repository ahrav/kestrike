use crate::classes::{is_digit, is_word};
use crate::rust_text::{FUNCTION, IGNORE, Lexeme, blank, code, lexemes};

use Lexeme::{Char, Comment, String, Unclosed};

type Spans = &'static [(Lexeme, usize, usize)];

/// Each case gives a Rust source and the spans `lexemes` yields for it, as byte offsets.
#[rustfmt::skip]
const CASES: &[(&str, Spans)] = &[
    ("/* never closed\n", &[(Unclosed, 0, 16)]),
    ("// A stale model.\n", &[(Comment, 0, 17)]),
    ("// The live model.\n", &[(Comment, 0, 18)]),
    ("\n    include!(\"unseen.rs\");\n", &[(String, 14, 25)]),
    ("#[cfg(not(refusal = \"keeps\"))]", &[(String, 20, 27)]),
    ("\naxiom /* reason */ fn hole();\n", &[(Comment, 7, 19)]),
    ("#[test]\nfn probe() { \"kept\"; }\n", &[(String, 21, 27)]),
    ("/* kani::proof\nfn harness() {}\n", &[(Unclosed, 0, 31)]),
    ("#[path = \"loop.rs\"]\nmod looped;\n", &[(String, 9, 18)]),
    ("#[path = \"extra.inc\"]\nmod extra;\n", &[(String, 9, 20)]),
    ("#[test]\nfn probe() { \"linted\"; }\n", &[(String, 21, 29)]),
    ("#[test]\nfn probe() { \"shared\"; }\n", &[(String, 21, 29)]),
    ("\n#[test]\nfn probe() { \"second\"; }\n", &[(String, 22, 30)]),
    ("\n#[test]\nfn probe() { \"planted\"; }\n", &[(String, 22, 31)]),
    ("#[path = \"flat/part.rs\"]\nmod part;\n", &[(String, 9, 23)]),
    ("const S: &str = \"kani::any_where\";\n", &[(String, 16, 33)]),
    ("/* const FAMILY: [History; 1] = [];\n", &[(Unclosed, 0, 36)]),
    ("#[path = \"storage/fill.rs\"]\nmod fill;\n", &[(String, 9, 26)]),
    ("// note\u{d} kani::stub();\nfn harness() {}\n", &[(Comment, 0, 22)]),
    ("\n    #[path = \"moved.rs\"]\n    mod inner;\n", &[(String, 14, 24)]),
    ("\n#[verifier:: /* reason */ external_body]\n", &[(Comment, 14, 26)]),
    ("include!(\"cycle.rs\");\n#[test]\nfn turns() {}\n", &[(String, 9, 19)]),
    ("fn harness() { kani /* gap */ ::\n    stub(); }\n", &[(Comment, 20, 29)]),
    ("#[path = \"../../../../../../outside.rs\"]\nmod m0;\n", &[(String, 9, 39)]),
    ("#[path = \"../../../../../undeclared.rs\"]\nmod m0;\n", &[(String, 9, 39)]),
    ("// note\u{d}/* \nfn harness() { kani::stub(); }\n// */\n", &[(Comment, 0, 11), (Comment, 43, 48)]),
    ("#[path = concat!(\"storage/\", \"fill.rs\")] mod fill;\n", &[(String, 17, 27), (String, 29, 38)]),
    ("const FAMILY: [History; 1] = [history(\"h-family\")];\n", &[(String, 38, 48)]),
    ("\n    const OPEN: &str = \"{\";\n#[test]\nfn witness() {}\n", &[(String, 24, 27)]),
    ("m!('r\"x\\\"/* /* */\");\nword.store(1, Ordering::Relaxed);\n", &[(String, 5, 18)]),
    ("word.store(1, Ordering::Relaxed);\n/* open\nword.swap(0);\n", &[(Unclosed, 34, 56)]),
    ("assert_eq!(winners.len(), 1, \"one entrant wins the latch\");", &[(String, 29, 57)]),
    ("// assert_eq!(winners.len(), 1, \"one entrant wins the latch\");", &[(Comment, 0, 62)]),
    ("assert!(durable, \"a slot returned before its block persisted\");", &[(String, 17, 61)]),
    ("\nproof fn hole() ensures false { assume /* reason */ (false); }\n", &[(Comment, 40, 52)]),
    ("include!(\"../../../../../crates/kestrike/src/storage/slot.rs\");\n", &[(String, 9, 61)]),
    ("#[path = \"../../../../../crates/kestrike/src/planted.rs\"]\nmod m0;\n", &[(String, 9, 56)]),
    ("/* a /* b */ word.swap(0); c */ word.store(1, Ordering::Relaxed);\n", &[(Comment, 0, 31)]),
    ("assert_eq!(counts(&storage), (0, 0), \"every registration ended once\");", &[(String, 37, 68)]),
    ("#[path = \"../../../../../crates/kestrike/src/storage/slot.rs\"]\nmod m0;\n", &[(String, 9, 61)]),
    ("#[path = \"../../../../../crates/kestrike/src/storage/extra.rs\"]\nmod m0;\n", &[(String, 9, 62)]),
    ("#[path = r\"../../../../../crates/kestrike/src/storage/slot.rs\"]\nmod m0;\n", &[(String, 9, 62)]),
    ("#[path  =  \"../../../../../crates/kestrike/src/storage/slot.rs\"]\nmod m0;\n", &[(String, 11, 63)]),
    ("#[test]\nfn at_main() {}\nmod control {\n#[test]\nfn probe() { \"second\"; }\n}\n", &[(String, 59, 67)]),
    ("#[path = \"../../../../../crates/kestrike/src/storage/sl\\x6ft.rs\"]\nmod m0;\n", &[(String, 9, 64)]),
    ("const S: &str = stringify!(a·r\"\\\"/*\");\nfn harness() { kani::stub(); }\n// */\n", &[(String, 30, 34), (Comment, 34, 76)]),
    ("const S: &str = stringify!(r#r\"\\\"/*\");\nfn harness() { kani::stub(); }\n// */\n", &[(String, 30, 36), (Comment, 70, 75)]),
    ("let _ = ['\\x41','\"']; let _ = \"/*\";\nword.store(1, Ordering::Relaxed);\n// */\n", &[(Char, 9, 15), (Char, 16, 19), (String, 30, 34), (Comment, 70, 75)]),
    ("#[path = \"../../../../../crates/kestrike/src/storage/undeclared.rs\"]\nmod m0;\n", &[(String, 9, 67)]),
    ("const S: &str = stringify!('r#r\"\\\"/*\");\nfn harness() { kani::stub(); }\n// */\n", &[(String, 31, 37), (Comment, 71, 76)]),
    ("#[path = \"../../../../../crates/kestrike/src/storage/planted/mod.rs\"]\nmod m0;\n", &[(String, 9, 68)]),
    ("assert_eq!( served, 8, \"the loop stops at the first check after the signal\" );", &[(String, 23, 75)]),
    ("\n    mod nested {\n#[test]\nfn probe() { \"planted\"; }\n    }\n#[test]\nfn probe() {}\n", &[(String, 39, 48)]),
    ("#[path = \"../../../../../crates/kestrike/src/storage/helpers/extra.rs\"]\nmod m0;\n", &[(String, 9, 70)]),
    ("let _ = ['\\u{0_41}','\"']; let _ = \"/*\";\nword.store(1, Ordering::Relaxed);\n// */\n", &[(Char, 9, 19), (Char, 20, 23), (String, 34, 38), (Comment, 74, 79)]),
    ("#[macro_use]\n// the prelude\nextern crate kani;\n#[solver(cadical)]\nfn harness() {}\n", &[(Comment, 13, 27)]),
    ("const S: &str = stringify!('x'br\"\\\"/*\");\nfn harness() { kani::assume(false); }\n// */\n", &[(Char, 27, 30), (String, 31, 35), (Comment, 35, 84)]),
    ("use std::include as inc;\ninc!(\"../../../../../crates/kestrike/src/storage/slot.rs\");\n", &[(String, 30, 82)]),
    ("#[kani::proof]\nconst S: &str = stringify!(\"x\"r\"\\\"/*\");\nfn harness() { kani::stub(); }\n// */\n", &[(String, 42, 45), (String, 45, 49), (Comment, 49, 91)]),
    ("assert!( taken == recorded(first) || taken == recorded(second), \"torn binding {taken:x?}\" );", &[(String, 64, 89)]),
    ("// #[kani::stub(a, b)]\n/* use kani::*; */\n#[kani::proof]\nfn harness() { kani::cover!(true); }\n", &[(Comment, 0, 22), (Comment, 23, 41)]),
    ("#[cfg_attr(kernel = \"x\", path = \"../../../../../crates/kestrike/src/storage/slot.rs\")]\nmod m0;\n", &[(String, 20, 23), (String, 32, 84)]),
    ("// kani::assume(false);\n/// `use kani as k;`\n// extern crate kani;\n// #[kanitool::proof]\nfn harness() {}\n", &[(Comment, 0, 23), (Comment, 24, 44), (Comment, 45, 66), (Comment, 67, 88)]),
    ("    check!(pin::<_, Sequential>(&ERA, &PIN).is_ok(), c\"pin refused\");\n    if CLOSED.load(Ordering::SeqCst) {\n", &[(String, 54, 67)]),
    ("#[cfg(a)]\nmod spliced {\n#[test]\nfn probe() { \"planted\"; }\n}\n#[cfg(not(a))]\nmod spliced {\n    include!(\"unseen.rs\");\n}\n", &[(String, 45, 54), (String, 102, 113)]),
    ("#[path = \"probe.rs\"]\n#[cfg(test)]\nmod probe;\nmod live;\nfn peek(state: &AtomicU64) -> u64 { state.load(Ordering::Acquire) }\n", &[(String, 9, 19)]),
    ("struct S(#[cfg(test)] extern \"C\" fn(u8) -> u8, AtomicU64);\nfn peek(state: &AtomicU64) -> u64 { state.load(Ordering::Acquire) }\n", &[(String, 29, 32)]),
    ("const M: [&str; 4] = [\"r\", \"#r\", r\"\\d\", r#\"a\"b\"#];\nconst B: &[u8] = (br\"x\");\n#[kani::proof]\nfn harness() { kani::cover!(true); }\n", &[(String, 22, 25), (String, 27, 31), (String, 33, 38), (String, 40, 48), (String, 70, 74)]),
    ("    let closed = CLOSED.load(Ordering::SeqCst);\n    check!(pin::<_, Sequential>(&ERA, &PIN).is_ok(), c\"pin refused\");\n    if closed {\n", &[(String, 102, 115)]),
    ("#[cfg(test)]\nextern \"C\" fn probe<A, B>() { X.store(1, Ordering::SeqCst); }\nfn peek(state: &AtomicU64) -> u64 { state.load(Ordering::Acquire) }\n", &[(String, 20, 23)]),
    ("/*\n#[path = \"../../../../../crates/kestrike/src/storage/credit.rs\"]\n*/\n#[path = r\"../../../../../crates/kestrike/src/storage/slot.rs\"]\nmod m0;\n", &[(Comment, 0, 70), (String, 80, 133)]),
    ("assert_eq!(\n    (word.lineage(), (word.0.load(Ordering::SeqCst) >> 8) & 15),\n    (1, WITHDRAWN),\n    \"readiness and authority fields remain intact\"\n);", &[(String, 101, 147)]),
    ("#[path = \"../../../../../crates/kestrike/src/storage/credit_model.rs\"]\nmod m0;\n#[path = \"../../../../../crates/kestrike/src/storage/credit.rs\"]\nmod m1;\n", &[(String, 9, 69), (String, 88, 142)]),
    ("assert_eq!(returned.load(std::sync::atomic::Ordering::Acquire), 0); assert!( !supervisor.verified(), \"an unacknowledged request verifies no containment\" );", &[(String, 101, 152)]),
    ("fn store(hold: &Hold<'_>", &[]),
    ("fn install<'s, P: Platform>", &[]),
    ("impl<'w, W: SeqWord> Busy<'w, W>", &[]),
    ("impl Cohort for PassCohort<'_, '_, '_, '_>", &[]),
    ("impl<P: Platform> Drop for FillFollower<'_, P>", &[]),
    ("mod kani {\n    pub fn assert(_: bool, _: &'static str) {}\n}\n", &[]),
];

#[test]
fn each_case_yields_its_spans() {
    for (text, spans) in CASES {
        assert_eq!(lexemes(text), *spans, "{text:?}");
    }
}

#[test]
fn the_view_blanks_each_byte_of_a_span_and_keeps_newlines_and_code() {
    for (text, spans) in CASES {
        let view = code(text);
        assert_eq!(view.len(), text.len(), "{text:?}");
        for (at, (&byte, &seen)) in text.as_bytes().iter().zip(view.as_bytes()).enumerate() {
            let inside = spans
                .iter()
                .any(|&(_, start, end)| (start..end).contains(&at));
            let expected = if inside && byte != b'\n' { b' ' } else { byte };
            assert_eq!(seen, expected, "{text:?} at {at}");
        }
    }
}

#[test]
fn a_blanked_code_point_holds_one_space_for_each_byte() {
    assert_eq!(blank("\u{e9}\n\u{65e5}"), "  \n   ");
}

#[test]
fn raw_strings_lifetimes_and_raw_identifiers_lex_as_the_prefix_rules_state() {
    let cases: &[(&str, Spans)] = &[
        ("m!('r\"x\\\"/* /* */\");", &[(String, 5, 18)]),
        ("let bar\"x\" = 1;", &[(String, 7, 10)]),
        ("br\"x\" cr#\"y\"#", &[(String, 1, 5), (String, 7, 13)]),
        ("abr\"x\"", &[(String, 3, 6)]),
        ("r#type \"s\"", &[(String, 7, 10)]),
        ("r#\"open", &[]),
        ("'a' 'ab 'r#x '1' '1", &[(Char, 0, 3), (Char, 13, 16)]),
        ("'\\u{0_41}' '\\x4' '\\''", &[(Char, 0, 10), (Char, 15, 18)]),
        ("/* a /* b */ c */ d", &[(Comment, 0, 17)]),
        ("x /* a /* b */ c", &[(Unclosed, 2, 16)]),
        ("\"a\\\"b\" \"open", &[(String, 0, 6)]),
        ("//* x\ny", &[(Comment, 0, 5)]),
    ];
    for (text, spans) in cases {
        assert_eq!(lexemes(text), *spans, "{text:?}");
    }
}

#[test]
fn the_ignore_pattern_matches_an_ignore_attribute_and_no_longer_word() {
    let found = |text: &str| {
        IGNORE
            .find_iter(text)
            .map(|m| m.as_str().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        found("#[ignore]\n#[ignore = \"slow\"]"),
        ["#[ignore]", "#[ignore = \"slow\"]"]
    );
    assert_eq!(
        found("#[cfg_attr(not(miri), ignore = \"x\")]\n#[cfg_attr(\n    miri,\n    ignore\n)]"),
        [
            "#[cfg_attr(not(miri), ignore = \"x\")]",
            "#[cfg_attr(\n    miri,\n    ignore\n)]"
        ]
    );
    assert!(
        found(concat!(
            "#[ignored]\n#[cfg_attr(miri, ",
            "ignored)]\n#[cfg_attr(miri, should_panic)]"
        ))
        .is_empty()
    );
}

#[test]
fn the_function_pattern_takes_the_attributes_and_the_name() {
    let found = |text: &str| {
        FUNCTION
            .find_iter(text)
            .map(|m| m.as_str().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        found("#[test]\n#[ignore]\nfn second() {}"),
        ["#[test]\n#[ignore]\nfn second"]
    );
    assert_eq!(
        found("pub(crate) async fn r#type() {}"),
        ["pub(crate) async fn r#type"]
    );
    assert_eq!(found("fn\u{3000}caf\u{e9}()"), ["fn\u{3000}caf\u{e9}"]);
    assert!(found("define() fnord").is_empty());
}

#[test]
fn word_and_digit_classes_are_unicode() {
    assert!(is_word('\u{e9}') && is_word('\u{663}') && is_word('\u{2460}') && is_word('_'));
    assert!(!is_word('\u{200c}') && !is_word('\u{300}') && !is_word('-'));
    assert!(
        is_digit('\u{663}')
            && is_digit('\u{1d7ce}')
            && !is_digit('\u{2460}')
            && !is_digit('\u{b2}')
    );
}
