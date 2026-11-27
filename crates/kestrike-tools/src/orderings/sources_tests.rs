use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use super::{
    Refusal, c_literals, diagnostic_sites, diagnostics, include_defects, kernel_texts, loads,
    loom_site, module_source, references, scope_files,
};
use crate::genmc::read_source;
use crate::json::{self, Text, Value};
use crate::paths::tests::Scratch;
use crate::rust_text::code;

const STORAGE: &str = "crates/kestrike/src/storage/mod.rs";
const CREDIT: &str = "crates/kestrike/src/storage/credit.rs";
const STEPS: &str = "crates/kestrike/src/storage/credit_steps.rs";
const FILL: &str = "crates/kestrike/src/storage/fill.rs";
const PACKAGE: &str = "verification/genmc/packages/kernels";
const FILL_MODEL: &str = "storage::fill_model::two_owners_on_one_key_and_a_servicer";
const MACRO_TOKENS: &str =
    "a module declaration inside a macro's tokens, which the scope rule cannot read";

fn top() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn committed(path: &str) -> String {
    read_source(&top(), path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// The committed text of `path` with its one `old` replaced by `new`.
fn planted(path: &str, old: &str, new: &str) -> String {
    let text = committed(path);
    assert_eq!(text.matches(old).count(), 1, "{old:?} in {path}");
    text.replacen(old, new, 1)
}

/// A planted text, or a read the reader refuses.
#[derive(Clone)]
enum Plant {
    Text(String),
    Refused,
}

/// A reader that gives each plant by path and the committed file otherwise.
fn reader(plants: Vec<(&str, Plant)>) -> impl Fn(&str) -> io::Result<String> {
    let plants: BTreeMap<String, Plant> = plants
        .into_iter()
        .map(|(path, plant)| (path.to_owned(), plant))
        .collect();
    move |path: &str| match plants.get(path) {
        Some(Plant::Text(text)) => Ok(text.clone()),
        Some(Plant::Refused) => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        None => read_source(&top(), path),
    }
}

/// A model source row: its label, its plants, the test, and the model source's text.
type SourceRow<'r> = (&'r str, Vec<(&'r str, Plant)>, &'r str, Option<String>);

/// The bare files, the path attributes with their names, and the refusal sentences a reading adds.
type Added = (Vec<String>, Vec<(String, Vec<String>)>, Vec<String>);

fn text(plant: String) -> Plant {
    Plant::Text(plant)
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("the copy's directory is made");
    for entry in fs::read_dir(from).expect("the package lists") {
        let entry = entry.expect("the entry reads");
        if entry.file_name() == "target" {
            continue;
        }
        let target = to.join(entry.file_name());
        if entry.file_type().expect("the entry's type reads").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("the file copies");
        }
    }
}

/// A copy of the kernel package under a scratch root with one more source, `src/planted.rs`: `text`,
/// with `{up}` the path from the source to the root, or one that includes each of `extra` by `#[path]`.
fn planted_package(extra: &[&str], text: Option<&str>) -> Scratch {
    let scratch = Scratch::new("sources");
    let package = scratch.0.join(PACKAGE);
    copy_tree(&top().join(PACKAGE), &package);
    let up = "../".repeat(Path::new(PACKAGE).join("src").iter().count());
    let source = text.map_or_else(
        || {
            extra
                .iter()
                .enumerate()
                .map(|(index, path)| format!("#[path = \"{{up}}{path}\"]\nmod m{index};\n"))
                .collect()
        },
        str::to_owned,
    );
    fs::write(package.join("src/planted.rs"), source.replace("{up}", &up))
        .expect("the planted source is written");
    scratch
}

fn package_of(scratch: &Scratch) -> PathBuf {
    scratch.0.join(PACKAGE)
}

fn messages(refusals: &[Refusal]) -> Vec<&str> {
    refusals.iter().map(Refusal::message).collect()
}

fn scope_messages(root: &Path, plants: Vec<(&str, Plant)>) -> Vec<String> {
    let read = reader(plants);
    let scope = scope_files(&root.join(PACKAGE), root, &read, &top()).expect("the scope reads");
    messages(scope.refusals())
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// A test's model source follows a bare, a path and an inline declaration, a commented decoy loads
/// nothing, a path declaration moves the source, and no source stands for an undeclared module, a
/// dropped declaration, one inside an unexpanded macro, or one a parent declares twice. Each row is one
/// reading: its plants, the test, and the path whose committed or planted text is its model source.
#[test]
fn a_loom_model_source_follows_inline_and_path_declared_modules() {
    let readiness = "crates/kestrike/src/storage/readiness.rs";
    let authority = "storage::readiness::authority_model::withdrawal_and_serving_publication_preserve_both_word_fields";
    let route = "net::client::route::route_model::a_read_racing_a_rebind_takes_one_binding_whole";
    let live = "crates/kestrike/src/storage/fill_model_v2.rs";
    let stale = "crates/kestrike/src/storage/fill_model_stale.rs";
    let stale_live =
        "#[cfg(all(test, loom))]\n#[path = \"fill_model_stale.rs\"]\nmod stale_model;\n";
    let decoyed = format!(
        "/*\n#[path = \"decoy.rs\"]\nmod authority_model;\n*/\n{}",
        committed(readiness)
    );
    let moved = planted(
        STORAGE,
        "\nmod fill_model;\n",
        "\n#[path = \"fill_model_v2.rs\"]\nmod fill_model;\n",
    );
    let in_macro = format!(
        "macro_rules! decoy {{\n    () => {{\n#[path = \"fill_model_stale.rs\"]\nmod fill_model;\n    }};\n}}\n{}{stale_live}",
        committed(STORAGE)
    );
    let in_comment = format!(
        "/*\n#[path = \"fill_model_stale.rs\"]\nmod fill_model;\n*/\n{}{stale_live}",
        committed(STORAGE)
    );
    let twice = planted(
        STORAGE,
        "#[cfg(all(test, loom))]\nmod fill_model;",
        "#[cfg(all(test, loom, any()))]\n#[path = \"fill_model_stale.rs\"]\nmod fill_model;\n#[cfg(all(test, loom))]\nmod fill_model;",
    );
    let beside = format!(
        "#[cfg(any())]\n#[path = \"authority_model_stale.rs\"]\nmod authority_model;\n{}",
        committed(readiness)
    );
    let stale_model = || (stale, text("// A stale model.\n".to_owned()));
    let rows: Vec<SourceRow<'_>> = vec![
        (
            "an inline module",
            vec![],
            authority,
            Some(committed(readiness)),
        ),
        (
            "a path declaration",
            vec![],
            route,
            Some(committed("crates/kestrike/src/net/client/route_model.rs")),
        ),
        (
            "a bare declaration",
            vec![],
            FILL_MODEL,
            Some(committed("crates/kestrike/src/storage/fill_model.rs")),
        ),
        ("an undeclared module", vec![], "undeclared::a_test", None),
        (
            "a commented decoy",
            vec![(readiness, text(decoyed.clone()))],
            authority,
            Some(decoyed),
        ),
        (
            "a moved module",
            vec![
                (STORAGE, text(moved)),
                (live, text("// The live model.\n".to_owned())),
            ],
            FILL_MODEL,
            Some("// The live model.\n".to_owned()),
        ),
        (
            "a dropped declaration",
            vec![(STORAGE, text(planted(STORAGE, "\nmod fill_model;\n", "\n")))],
            FILL_MODEL,
            None,
        ),
        (
            "a path declaration among a macro's tokens",
            vec![(STORAGE, text(in_macro)), stale_model()],
            FILL_MODEL,
            Some(committed("crates/kestrike/src/storage/fill_model.rs")),
        ),
        (
            "a path declaration in a comment",
            vec![(STORAGE, text(in_comment)), stale_model()],
            FILL_MODEL,
            Some(committed("crates/kestrike/src/storage/fill_model.rs")),
        ),
        (
            "a declaration in an unexpanded macro",
            vec![(
                STORAGE,
                text(planted(
                    STORAGE,
                    "\nmod fill_model;\n",
                    "\nmacro_rules! decoy {\n    () => {\n        mod fill_model;\n    };\n}\n",
                )),
            )],
            FILL_MODEL,
            None,
        ),
        (
            "a module declared twice",
            vec![(STORAGE, text(twice)), stale_model()],
            FILL_MODEL,
            None,
        ),
        (
            "a path declaration beside an inline module",
            vec![
                (readiness, text(beside)),
                (
                    "crates/kestrike/src/storage/authority_model_stale.rs",
                    text("// A stale model.\n".to_owned()),
                ),
            ],
            authority,
            None,
        ),
    ];
    for (label, plants, test, expected) in rows {
        let read = reader(plants);
        assert_eq!(module_source(test, &read), expected, "{label}");
    }
}

/// The grace model's message literals hold `anchor released twice` in two assertions, so no one
/// assertion names a failure that holds it.
#[test]
fn a_loom_failure_two_message_literals_hold_is_refused() {
    let model = committed("crates/kestrike/src/storage/grace_model.rs");
    let holding = diagnostics(&model)
        .iter()
        .filter(|content| *content == "protection violated: anchor released twice")
        .count();
    assert_eq!(holding, 2);
}

/// A planted assertion whose message extends another's makes two message literals hold the shorter
/// text.
#[test]
fn a_loom_failure_another_message_literal_extends_is_refused() {
    let anchor = "\"protection violated: anchor released under a pinned reader\"";
    let extended = planted(
        "crates/kestrike/src/storage/grace_model.rs",
        anchor,
        &format!(
            "{anchor});\n        assert!(false, \"protection violated: anchor released under a pinned reader twice\""
        ),
    );
    let holding = diagnostics(&extended)
        .iter()
        .filter(|content| content.contains("anchor released under a pinned reader"))
        .count();
    assert_eq!(holding, 2);
}

/// A `should_panic` attribute's `expected` text is no message literal: the scan model holds `torn copy
/// of B` only there, and the fill model's departure message stays a message literal, on one line, with
/// its attribute replaced by a bare `#[should_panic]`.
#[test]
fn a_loom_failure_only_an_attribute_holds_is_refused() {
    let scan = committed("crates/kestrike/src/index/scan_model.rs");
    assert!(scan.contains("#[should_panic(expected = \"torn copy of B\")]"));
    assert!(
        !diagnostics(&scan)
            .iter()
            .any(|content| content.contains("torn copy of B"))
    );
    let failure = "a departed record whose owner had not ended";
    let model = "crates/kestrike/src/storage/fill_model.rs";
    let attribute = format!("#[should_panic(expected = \"{failure}\")]");
    let source = committed(model);
    assert!(source.contains(&attribute));
    let read = reader(vec![(
        model,
        text(source.replace(&attribute, "#[should_panic]")),
    )]);
    let found = loom_site(FILL_MODEL, failure, &read).map(|(path, _)| path);
    assert_eq!(found.as_deref(), Some(model));
}

/// A `check!` message is a `c"..."` literal that is the call's last argument: the same literal in a
/// comment, outside a `check!` call or in its condition is none, and a plain string beside it leaves it
/// one.
#[test]
fn a_genmc_failure_spelled_c_only_in_a_comment_is_refused() {
    let literal = "c\"a follower's record was freed or reissued under it\"";
    let plain = &literal[1..];
    let call = format!("check!(false, {literal})");
    let kernel = committed(&format!("{PACKAGE}/src/join_kernel.rs"));
    assert_eq!(kernel.matches(&call).count(), 1);
    let rows = [
        (
            "a comment",
            format!("check!(false, {plain} /* {literal} */)"),
            0,
        ),
        (
            "the literal outside check!",
            format!("check!(false, {plain}); let _stale = ({literal})"),
            0,
        ),
        (
            "the literal in the condition",
            format!("check!({literal}.is_empty(), c\"another message\")"),
            0,
        ),
        (
            "a plain duplicate beside it",
            format!("check!(false, {literal}); let _plain = ({plain})"),
            1,
        ),
    ];
    for (label, new, count) in rows {
        let found = c_literals(&kernel.replacen(&call, &new, 1))
            .iter()
            .filter(|message| *message == "a follower's record was freed or reissued under it")
            .count();
        assert_eq!(found, count, "{label}");
    }
}

/// Python's `\b` holds beside a word character of any script: a name a word character extends is no
/// `check!` and no assertion, and a `c` prefix a word character precedes is no C string. Each row is a
/// text and the messages and the (content, line) sites it gives.
#[test]
fn a_word_character_outside_ascii_bounds_each_name() {
    let checks = "check!(false, c\"one\");\ncheck!(x, c\"two\" , );\n\u{e9}check!(x, c\"three\");\n \
                  check!(\u{e9}, xc\"four\");\ncheck!(x, \u{b2}c\"five\");\n";
    assert_eq!(c_literals(checks), ["one", "two"]);
    let asserts = "assert!(x, \"a\");\n\u{e9}assert!(x, \"f\");\n\u{b2}panic!(\"g\");\nmy_assert!(x, \"e\");\n\
                   x . \n expect (\"d\");\n";
    assert_eq!(
        diagnostic_sites(asserts),
        [("a".to_owned(), 1), ("d".to_owned(), 6)]
    );
}

/// The 40 code points before a literal's bracket hold its macro's name: characters outside ASCII in the
/// window widen it by none, and a message on a later line than its name reports the name's line.
#[test]
fn a_window_counts_code_points_of_the_source() {
    let source = "assert!(\n    cond,\n    \"far from its macro name\" \n);\n\
                  assert!(c, \"\u{fc}n\u{ef}code \u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\u{eb}\", \"k\");\n";
    let found: Vec<usize> = diagnostic_sites(source)
        .into_iter()
        .map(|(_, line)| line)
        .collect();
    assert_eq!(found, [1, 5, 5]);
}

/// An `include!` call, spelled whole or through a renamed import, is refused by the planted source's line.
#[test]
fn an_include_macro_in_a_package_source_is_refused() {
    for source in [
        "include!(\"{up}crates/kestrike/src/storage/slot.rs\");\n",
        "use std::include as inc;\ninc!(\"{up}crates/kestrike/src/storage/slot.rs\");\n",
    ] {
        let scratch = planted_package(&[], Some(source));
        let package = package_of(&scratch);
        let kernels = kernel_texts(&package).expect("the package reads");
        let defects = include_defects(&package, &kernels).expect("the includes resolve");
        assert_eq!(
            messages(&defects),
            [
                "kernels/src/planted.rs:1: an include! macro, whose source the scope rule does not read"
            ],
            "{source}"
        );
    }
}

/// A path attribute the include scanner misses, a scanner match outside live code, an escaped include
/// path and an include that is no Rust source of the package are each refused by line.
#[test]
fn a_path_attribute_the_include_scanner_misses_is_refused() {
    let slot = "{up}crates/kestrike/src/storage/slot.rs";
    let missed = "kernels/src/planted.rs:1: a path attribute the include scanner misses";
    let rows: [(&str, String, Vec<String>); 5] = [
        ("a raw string", format!("#[path = r\"{slot}\"]\nmod m0;\n"), vec![missed.to_owned()]),
        ("other spacing", format!("#[path  =  \"{slot}\"]\nmod m0;\n"), vec![missed.to_owned()]),
        ("a conditional attribute", format!("#[cfg_attr(kernel = \"x\", path = \"{slot}\")]\nmod m0;\n"), vec![missed.to_owned()]),
        (
            "a commented include beside a missed one",
            format!("/*\n#[path = \"{{up}}{CREDIT}\"]\n*/\n#[path = r\"{slot}\"]\nmod m0;\n"),
            vec![
                "kernels/src/planted.rs:4: a path attribute the include scanner misses".to_owned(),
                "kernels/src/planted.rs:2: the include scanner reads a path attribute outside live code".to_owned(),
            ],
        ),
        (
            "an escaped include",
            "#[path = \"{up}crates/kestrike/src/storage/sl\\x6ft.rs\"]\nmod m0;\n".to_owned(),
            vec!["kernels/src/planted.rs:1: the include path '../../../../../crates/kestrike/src/storage/sl\\\\x6ft.rs' holds an escape".to_owned()],
        ),
    ];
    for (label, source, expected) in rows {
        let scratch = planted_package(&[], Some(&source));
        let package = package_of(&scratch);
        let kernels = kernel_texts(&package).expect("the package reads");
        let defects = include_defects(&package, &kernels).expect("the includes resolve");
        assert_eq!(messages(&defects), expected, "{label}");
    }
    let scratch = planted_package(&[], Some("#[path = \"extra.inc\"]\nmod extra;\n"));
    let package = package_of(&scratch);
    fs::write(
        package.join("src/extra.inc"),
        "#[path = \"../../../../../../crates/kestrike/src/storage/slot.rs\"]\nmod m0;\n",
    )
    .expect("the include is written");
    let kernels = kernel_texts(&package).expect("the package reads");
    let defects = include_defects(&package, &kernels).expect("the includes resolve");
    assert_eq!(
        messages(&defects),
        [
            "kernels/src/planted.rs:1: the include 'extra.inc' is no Rust source of the package the scan reads"
        ]
    );
}

/// A directory named like a source is no kernel text.
#[test]
fn a_directory_named_like_a_source_is_skipped() {
    let scratch = planted_package(&[], Some(""));
    let package = package_of(&scratch);
    fs::create_dir(package.join("src/spare.rs")).expect("the directory is made");
    let names: Vec<String> = kernel_texts(&package)
        .expect("the package reads")
        .into_keys()
        .collect();
    let mut expected: Vec<String> = kernel_texts(&top().join(PACKAGE))
        .expect("the committed package reads")
        .into_keys()
        .collect();
    expected.push("src/planted.rs".to_owned());
    expected.sort();
    assert_eq!(names, expected);
}

/// A link that loops and that no include names is passed over like a directory named like a source;
/// an include that resolves to it is the error of the include's resolution, not a kernel text's.
#[test]
fn a_symlink_loop_in_the_kernel_package_is_never_accepted() {
    let scratch = planted_package(&[], Some("#[path = \"loop.rs\"]\nmod looped;\n"));
    let package = package_of(&scratch);
    symlink("loop.rs", package.join("src/loop.rs")).expect("the loop is made");
    let kernels = kernel_texts(&package).expect("the package reads");
    assert!(!kernels.contains_key("src/loop.rs"));
    assert!(include_defects(&package, &kernels).is_err());
}

/// Each tracked Rust source of the committed kernel package is a kernel text with its file's text,
/// build state aside, as a run judges its GenMC cases with them.
#[test]
fn a_genmc_lane_past_its_deadline_gives_no_verdict_for_every_case() {
    let package = top().join(PACKAGE);
    let kernels = kernel_texts(&package).expect("the committed package reads");
    for (path, source) in &kernels {
        assert_eq!(source, &committed(&format!("{PACKAGE}/{path}")), "{path}");
    }
    assert!(kernels.contains_key("src/join_kernel.rs"));
    assert!(kernels.contains_key("ops/src/lib.rs"));
}

/// Each cataloged GenMC failure is the text of a `check!` message of the kernel text of its case's
/// family, the case name's leading lowercase letters.
#[test]
fn each_cataloged_genmc_failure_lies_in_its_case_family_kernel() {
    let kernels = kernel_texts(&top().join(PACKAGE)).expect("the committed package reads");
    let catalog = json::parse(&committed("verification/orderings/expected.json"))
        .expect("the catalog parses");
    let Value::Object(catalog) = catalog else {
        panic!("the catalog is an object");
    };
    let Some(Value::Array(rows)) = catalog.get("rows") else {
        panic!("the catalog holds rows");
    };
    let mut checked = 0;
    for row in rows {
        let Value::Object(row) = row else { continue };
        let needs = row.get("unrun").and_then(|unrun| match unrun {
            Value::Object(unrun) => unrun.get("needs"),
            _ => None,
        });
        let Some(Value::Array(needs)) = needs else {
            continue;
        };
        for need in needs {
            let Value::Object(need) = need else { continue };
            let (
                Some(Value::String(lane)),
                Some(Value::String(failure)),
                Some(Value::Array(tests)),
            ) = (need.get("lane"), need.get("failure"), need.get("tests"))
            else {
                continue;
            };
            if *lane != "genmc" {
                continue;
            }
            for test in tests {
                let Value::String(case) = test else { continue };
                let case = case.to_str().expect("a case name is UTF-8");
                let family: String = case.chars().take_while(char::is_ascii_lowercase).collect();
                let source = &kernels[&format!("src/{family}_kernel.rs")];
                let failure = failure.to_str().expect("a failure is UTF-8");
                assert_eq!(
                    c_literals(source)
                        .iter()
                        .filter(|message| *message == failure)
                        .count(),
                    1,
                    "{case}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 0);
}

/// A declaration in a comment or a string declares nothing: the reading of the planted module file is
/// the committed file's.
#[test]
fn a_commented_declaration_declares_nothing() {
    let source = planted(
        STORAGE,
        "\nmod credit;\n",
        "\n// mod credit_steps;\n// #[path = \"credit_steps.rs\"]\nconst _DECLARED: &str = \"mod credit_steps;\";\nmod credit;\n",
    );
    let committed_source = committed(STORAGE);
    let child = "crates/kestrike/src/storage";
    assert_eq!(
        loads(STORAGE, child, &source, &code(&source)),
        loads(STORAGE, child, &committed_source, &code(&committed_source))
    );
}

/// A `mod` keyword or a path attribute among a macro's tokens is refused on the macro's line, whether
/// the macro is a definition or an invocation; a macro that declares no module is no refusal. Each row
/// appends a text to the module file, the moved one where it redirects `fill`, and names the line of the
/// refusal after the file's own lines.
#[test]
fn a_module_declaration_inside_a_macro_is_refused() {
    let moved = planted(
        STORAGE,
        "\nmod fill;\n",
        "\n#[path = \"fill_v2.rs\"]\nmod fill;\n",
    );
    let base = committed(STORAGE);
    let rows: [(&str, &str, &str, usize); 12] = [
        (
            "an unexpanded definition beside a redirected module",
            &moved,
            "macro_rules! decoy {\n    () => {\n        mod fill;\n    };\n}\n",
            1,
        ),
        (
            "a definition in parentheses",
            &moved,
            "macro_rules! decoy (\n    () => {\n        mod fill;\n    };\n);\n",
            1,
        ),
        (
            "a definition named by a raw identifier",
            &moved,
            "macro_rules! r#decoy {\n    () => {\n        mod fill;\n    };\n}\n",
            1,
        ),
        (
            "a definition with a spaced bang",
            &moved,
            "macro_rules ! decoy {\n    () => {\n        mod fill;\n    };\n}\n",
            1,
        ),
        (
            "an invocation that drops its tokens",
            &moved,
            "ignore! {\n    mod fill;\n}\n",
            1,
        ),
        (
            "an invocation in parentheses",
            &moved,
            "const _DECOY: &str = stringify!(mod fill;);\n",
            1,
        ),
        (
            "an invoked definition beside a test-only declaration",
            &base,
            "macro_rules! live {\n    () => {\n        #[cfg(not(test))]\n        mod credit_steps;\n    };\n}\nlive!();\n",
            1,
        ),
        (
            "a path attribute in a definition",
            &base,
            "macro_rules! live {\n    () => {\n        #[path = \"credit_steps.rs\"]\n        mod steps_live;\n    };\n}\nlive!();\n",
            1,
        ),
        (
            "a module named by a fragment",
            &base,
            "macro_rules! declare {\n    ($name:ident) => {\n        mod $name;\n    };\n}\ndeclare!(credit_steps);\n",
            1,
        ),
        (
            "a module whose `;` the macro supplies",
            &base,
            "#[cfg(not(all(test, loom)))]\ndeclare!(mod credit_steps);\n",
            2,
        ),
        (
            "a module a macro declares from an inline block",
            &base,
            "macro_rules! child {\n    ($kw:tt $name:ident $body:tt) => {\n        $kw $name;\n    };\n}\nchild!(mod credit_steps {});\n",
            6,
        ),
        (
            "an inline module in a definition",
            &base,
            "macro_rules! plain {\n    () => {\n        mod inner {}\n    };\n}\nplain!();\n",
            1,
        ),
    ];
    for (label, file, appended, offset) in rows {
        let source = format!("{file}{appended}");
        let declared = loads(
            STORAGE,
            "crates/kestrike/src/storage",
            &source,
            &code(&source),
        );
        let line = file.matches('\n').count() + offset;
        let expected = format!("{STORAGE}:{line}: {MACRO_TOKENS}");
        assert_eq!(
            messages(declared.refusals()),
            [expected.as_str()],
            "{label}"
        );
    }
    let plain = format!(
        "{base}macro_rules! plain {{\n    () => {{\n        fn helper() {{}}\n    }};\n}}\nplain!();\n"
    );
    assert_eq!(
        loads(
            STORAGE,
            "crates/kestrike/src/storage",
            &plain,
            &code(&plain)
        )
        .refusals(),
        []
    );
}

/// The files the reading of `appended` after the committed module file adds to its bare declarations,
/// and the path attributes it adds.
fn added(file: &str, appended: &str) -> Added {
    let child = "crates/kestrike/src/storage";
    let base = loads(STORAGE, child, file, &code(file));
    let source = format!("{file}{appended}");
    let declared = loads(STORAGE, child, &source, &code(&source));
    let bare = declared.bare().difference(base.bare()).cloned().collect();
    let attributed = declared
        .attributed()
        .iter()
        .filter(|entry| !base.attributed().contains(entry))
        .map(|(path, names)| (path.clone(), names.iter().cloned().collect()))
        .collect();
    let refusals = messages(declared.refusals())
        .into_iter()
        .map(str::to_owned)
        .collect();
    (bare, attributed, refusals)
}

/// A declaration inside an inline module loads from that module's directory, a bare one and a path
/// attribute alike, and a path attribute may climb out of it.
#[test]
fn a_declaration_in_an_inline_module_loads_from_that_modules_directory() {
    let moved = planted(
        STORAGE,
        "\nmod fill;\n",
        "\n#[path = \"fill_v2.rs\"]\nmod fill;\n",
    );
    let base = committed(STORAGE);
    let storage = |rest: &str| format!("crates/kestrike/src/storage/{rest}");
    let rows: [(&str, &str, &str, Added); 4] = [
        (
            "a bare declaration in an inline module",
            &moved,
            "mod inner {\n    mod fill;\n}\n",
            (
                vec![storage("inner/fill.rs"), storage("inner/fill/mod.rs")],
                vec![],
                vec![],
            ),
        ),
        (
            "a nested declaration",
            &base,
            "mod nested {\n    mod credit_steps;\n}\n",
            (
                vec![
                    storage("nested/credit_steps.rs"),
                    storage("nested/credit_steps/mod.rs"),
                ],
                vec![],
                vec![],
            ),
        ),
        (
            "a nested path attribute",
            &base,
            "mod nested {\n    #[path = \"credit_steps.rs\"]\n    mod steps;\n}\n",
            (
                vec![],
                vec![(
                    storage("nested/credit_steps.rs"),
                    vec!["nested::steps".to_owned()],
                )],
                vec![],
            ),
        ),
        (
            "a path attribute that climbs",
            &base,
            "mod nested {\n    mod deeper {\n        #[path = \"../../credit_steps.rs\"]\n        mod steps;\n    }\n}\n",
            (
                vec![],
                vec![(STEPS.to_owned(), vec!["nested::deeper::steps".to_owned()])],
                vec![],
            ),
        ),
    ];
    for (label, file, appended, expected) in rows {
        assert_eq!(added(file, appended), expected, "{label}");
    }
}

/// A module named by a raw identifier loads its file by the name without `r#`, as a bare declaration,
/// a path attribute and an inline module; among a macro's tokens it is refused.
#[test]
fn a_module_declared_by_a_raw_identifier_loads_its_file() {
    let base = committed(STORAGE);
    let line = base.matches('\n').count() + 1;
    let rows: [(&str, &str, Added); 4] = [
        (
            "a path attribute",
            "#[cfg(not(test))]\n#[path = \"credit_steps.rs\"]\nmod r#steps;\n",
            (
                vec![],
                vec![(STEPS.to_owned(), vec!["steps".to_owned()])],
                vec![],
            ),
        ),
        (
            "an inline module",
            "#[cfg(not(test))]\nmod r#storage {\n    #[path = \"../credit_steps.rs\"]\n    mod steps;\n}\n",
            (
                vec![],
                vec![(STEPS.to_owned(), vec!["storage::steps".to_owned()])],
                vec![],
            ),
        ),
        (
            "a declaration",
            "#[cfg(not(test))]\nmod r#planted_steps;\n",
            (
                vec![
                    "crates/kestrike/src/storage/planted_steps.rs".to_owned(),
                    "crates/kestrike/src/storage/planted_steps/mod.rs".to_owned(),
                ],
                vec![],
                vec![],
            ),
        ),
        (
            "a declaration among a macro's tokens",
            "ignore! {\n    mod r#credit_steps;\n}\n",
            (
                vec![],
                vec![],
                vec![format!("{STORAGE}:{line}: {MACRO_TOKENS}")],
            ),
        ),
    ];
    for (label, appended, expected) in rows {
        assert_eq!(added(&base, appended), expected, "{label}");
    }
    let live = format!("{base}#[cfg(not(test))]\nmod r#credit_steps;\n");
    let read = reader(vec![(STORAGE, text(live))]);
    let scope = scope_files(&top().join(PACKAGE), &top(), &read, &top()).expect("the scope reads");
    assert!(scope.included().iter().any(|path| path == STEPS));
    let raw = planted(STORAGE, "\nmod fill;\n", "\nmod r#fill;\n");
    let child = "crates/kestrike/src/storage";
    assert_eq!(
        loads(STORAGE, child, &raw, &code(&raw)),
        loads(STORAGE, child, &base, &code(&base))
    );
}

/// A model support file and the credit steps the package includes stand as excluded, since only
/// test-only items declare them.
#[test]
fn a_model_support_file_the_package_includes_is_excluded() {
    let scratch = planted_package(
        &["crates/kestrike/src/storage/credit_model.rs", CREDIT],
        None,
    );
    let read = reader(vec![]);
    let scope =
        scope_files(&package_of(&scratch), &scratch.0, &read, &top()).expect("the scope reads");
    assert_eq!(
        scope.excluded(),
        ["crates/kestrike/src/storage/credit_model.rs", STEPS]
    );
}

/// A directory module stands as its parent's declaration does: production under a live one, excluded
/// under a test-only one.
#[test]
fn a_directory_module_is_classified_by_its_parent() {
    let include = "crates/kestrike/src/storage/planted/mod.rs";
    let scratch = planted_package(&[include], None);
    let rows = [
        (
            "a live declaration",
            "\nmod slot;\nmod planted;\n",
            (true, false),
        ),
        (
            "a test-only declaration",
            "\nmod slot;\n#[cfg(test)]\nmod planted;\n",
            (false, true),
        ),
    ];
    for (label, declaration, expected) in rows {
        let read = reader(vec![(
            STORAGE,
            text(planted(STORAGE, "\nmod slot;\n", declaration)),
        )]);
        let scope =
            scope_files(&package_of(&scratch), &scratch.0, &read, &top()).expect("the scope reads");
        let standing = (
            scope.included().iter().any(|path| path == include),
            scope.excluded().iter().any(|path| path == include),
        );
        assert_eq!(standing, expected, "{label}");
    }
}

/// A file that only a path attribute in another directory's source declares is refused.
#[test]
fn a_file_declared_only_from_another_directory_is_refused() {
    let holder = "crates/kestrike/src/failover/reconcile_tests.rs";
    let moved = planted(
        STORAGE,
        "\nmod fill;\n",
        "\n#[path = \"fill_v2.rs\"]\nmod fill;\n",
    );
    let decoyed = format!(
        "{}\n#[path = \"../storage/fill.rs\"]\nmod decoy;\n",
        committed(holder)
    );
    let found = scope_messages(
        &top(),
        vec![(STORAGE, text(moved)), (holder, text(decoyed))],
    );
    let expected = format!(
        "{FILL} is declared only by a path attribute outside its module files and the crate root, in a \
         file whose place in the crate the scope rule does not read"
    );
    assert!(found.contains(&expected), "{found:?}");
}

/// An include that no module file declares is refused with the module files searched: its directory's
/// `mod.rs` and sibling first, then the files the crate's path attributes name there. A module file
/// that would declare it and cannot be read is refused with the reader's error.
#[test]
fn an_include_no_module_file_declares_is_refused() {
    let include = "crates/kestrike/src/storage/undeclared.rs";
    let scratch = planted_package(&[include], None);
    let found = scope_messages(&scratch.0, vec![]);
    let head = format!(
        "the kernel package includes {include} and no module file declares it through declarations \
         that reach the crate root; searched ['{STORAGE}', 'crates/kestrike/src/storage.rs', "
    );
    let undeclared: Vec<&String> = found
        .iter()
        .filter(|message| message.starts_with(&head))
        .collect();
    assert_eq!(undeclared.len(), 1, "{found:?}");
    assert!(undeclared[0].ends_with("] and the crate's path attributes"));
    let refused = scope_messages(&scratch.0, vec![(STORAGE, Plant::Refused)]);
    let expected = format!(
        "{STORAGE} cannot be read to classify {include}: {}",
        io::Error::from(io::ErrorKind::PermissionDenied)
    );
    assert!(refused.contains(&expected), "{refused:?}");
    let extra = "crates/kestrike/src/storage/extra.rs";
    let scratch = planted_package(&[extra], None);
    let elsewhere = format!(
        "{}\n#[cfg(test)]\n#[path = \"tests/extra.rs\"]\nmod extra;\n",
        committed(STORAGE)
    );
    let found = scope_messages(&scratch.0, vec![(STORAGE, text(elsewhere))]);
    let head = format!("the kernel package includes {extra} and no module file declares it");
    assert_eq!(
        found
            .iter()
            .filter(|message| message.starts_with(&head))
            .count(),
        1,
        "{found:?}"
    );
    let scratch = planted_package(&["undeclared.rs"], None);
    let found = scope_messages(&scratch.0, vec![]);
    let head = "the kernel package includes undeclared.rs and no module file declares it";
    assert_eq!(
        found
            .iter()
            .filter(|message| message.starts_with(head))
            .count(),
        1,
        "{found:?}"
    );
}

/// An include that resolves outside the checkout is refused by its resolved path.
#[test]
fn an_include_outside_the_repository_is_refused() {
    let scratch = planted_package(&["../outside.rs"], None);
    let found = scope_messages(&scratch.0, vec![]);
    let outside = scratch
        .0
        .parent()
        .expect("the scratch root has a parent")
        .join("outside.rs");
    let expected = format!(
        "the kernel package includes {}, outside the repository",
        outside.display()
    );
    assert_eq!(found, [expected]);
}

/// The committed obligation records, with one loom control also listed under its record's tests.
fn records_with_control_tested(control: &str) -> Value {
    let mut records =
        json::parse(&committed("verification/obligations.json")).expect("the records parse");
    let Value::Object(object) = &mut records else {
        panic!("the records are an object");
    };
    let Some(Value::Array(list)) = object.get_mut("records") else {
        panic!("the records hold a list");
    };
    let record = list
        .iter_mut()
        .find_map(|record| match record {
            Value::Object(record) => {
                let controls = match record.get("controls") {
                    Some(Value::Array(controls)) => controls.clone(),
                    _ => Vec::new(),
                };
                controls
                    .iter()
                    .any(|entry| matches!(entry, Value::Object(entry) if entry.get("test") == Some(&Value::String(Text::from(control)))))
                    .then_some(record)
            }
            _ => None,
        })
        .expect("a loom record lists the control");
    let Some(Value::Array(tests)) = record.get_mut("tests") else {
        panic!("the record lists its tests");
    };
    tests.push(Value::String(Text::from(control)));
    records
}

/// A loom control that its record also lists under `tests` is no positive loom test and stays a twin.
#[test]
fn a_control_also_listed_under_tests_is_no_positive_test() {
    let control =
        "storage::fill_model::negative_control_a_relaxed_departure_loses_the_owners_last_write";
    let declared = json::parse(&committed("verification/genmc/expected.json"))
        .expect("the declaration parses");
    let litmus =
        json::parse(&committed("verification/rc11/expected.json")).expect("the litmus list parses");
    let found = references(
        &declared,
        &litmus,
        &records_with_control_tested(control),
        &top(),
    )
    .expect("the references read");
    let name = Text::from(control);
    let standing = (
        found
            .positive("loom")
            .expect("loom has positive tests")
            .contains(&name),
        found.twins("loom").expect("loom has twins").contains(&name),
    );
    assert_eq!(standing, (false, true));
}

/// A declaration whose members have another shape reads no references.
#[test]
fn a_record_list_of_another_shape_reads_no_references() {
    let declared = json::parse(&committed("verification/genmc/expected.json"))
        .expect("the declaration parses");
    let litmus =
        json::parse(&committed("verification/rc11/expected.json")).expect("the litmus list parses");
    let records = json::parse("{\"records\": [\"loom\"]}").expect("the plant parses");
    assert!(matches!(
        references(&declared, &litmus, &records, &top()),
        Err(super::ReferenceError::Shape(_))
    ));
}
