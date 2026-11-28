use std::collections::{BTreeMap, BTreeSet};

use super::checked;
use crate::json;

/// The command prints the report the check gives, and nothing else, and returns its code: a refusing
/// report with 1 and an unreadable input's report with 2.
#[test]
fn main_prints_only_the_report_and_returns_its_exit_code() {
    for (report, code) in [
        (
            r#"{"refusals": [{"refusal": "find", "message": "planted"}], "credited": false}"#,
            1,
        ),
        (
            r#"{"error": "unreadable catalog or declaration: planted"}"#,
            2,
        ),
    ] {
        let report = json::parse(report).expect("parses");
        let mut out = Vec::new();
        assert_eq!(checked(|| (report.clone(), code), &mut out), code);
        let printed = String::from_utf8(out).expect("UTF-8");
        assert_eq!(json::parse(&printed).expect("one JSON value"), report);
        assert_eq!(printed, format!("{}\n", json::indented_in_order(&report)));
    }
}

/// Each refusal the check refuses by name, as the help lists them.
fn documented(help: &str) -> BTreeSet<String> {
    let listed = help
        .split_once("`check` refuses, each by name:")
        .and_then(|(_, rest)| rest.split_once("`check` prints"))
        .map(|(listed, _)| listed)
        .expect("the help lists the refusals");
    let mut names = BTreeSet::new();
    let named = |text: &str| -> Option<String> {
        let (name, _) = text.split_once("`:")?;
        name.chars()
            .all(|c| c.is_ascii_lowercase() || c == ' ')
            .then(|| name.to_owned())
            .filter(|name| !name.is_empty())
    };
    for line in listed.lines() {
        if let Some(rest) = line.strip_prefix("- `") {
            names.extend(named(rest));
        }
        for (_, rest) in line
            .match_indices("; `")
            .map(|(at, _)| ((), &line[at + 3..]))
        {
            names.extend(named(rest));
        }
    }
    names
}

/// The check's cases that plant each documented refusal, by the test's name.
const CLAUSES: [(&str, &[&str]); 11] = [
    (
        "unrowed site",
        &[
            "a_new_acquire_load_without_a_row_is_refused_by_file_and_token",
            "a_new_fence_without_a_row_is_refused",
            "a_site_after_a_test_only_element_is_a_site",
            "an_ordering_nested_in_a_fence_named_call_is_its_own_site",
            "a_hook_with_a_body_is_a_fence_site",
        ],
    ),
    (
        "site rows",
        &[
            "a_site_in_two_rows_is_refused",
            "an_acqrel_site_needs_a_row_to_acquire_and_a_row_to_release",
        ],
    ),
    (
        "find",
        &[
            "a_cataloged_release_weakened_in_the_source_is_refused_by_row",
            "an_emptied_fill_forwarder_is_refused",
            "a_find_that_occurs_twice_is_refused",
            "an_empty_scoped_file_refuses_each_of_its_rows",
            "a_find_that_holds_two_sites_is_refused",
            "a_find_whose_site_moved_to_a_comment_holds_no_site",
            "an_ordering_nested_in_a_fence_named_call_is_its_own_site",
        ],
    ),
    (
        "step",
        &[
            "a_replace_that_weakens_seqcst_to_relaxed_is_refused",
            "an_op_the_matcher_reads_otherwise_is_refused",
            "a_site_whose_op_the_matcher_cannot_read_is_refused",
            "a_fence_row_that_keeps_the_call_is_refused",
            "a_rooted_fence_row_deletes_the_whole_path",
            "a_strength_constant_takes_its_op_from_the_code",
            "a_strength_constant_passed_to_two_ops_is_unread",
        ],
    ),
    (
        "spelling",
        &[
            "a_hidden_spelling_of_an_ordering_is_refused",
            "a_forwarder_that_passes_another_fence_is_refused",
            "a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused",
            "a_test_only_element_the_matcher_cuts_is_refused",
        ],
    ),
    (
        "scope file",
        &[
            "a_production_file_the_package_includes_and_files_lacks_is_refused",
            "a_listed_file_the_package_does_not_include_is_refused",
            "an_unreadable_scope_file_is_refused",
            "a_module_declaration_inside_a_macro_is_refused",
            "a_module_declared_by_a_raw_identifier_loads_its_file",
            "a_declaration_in_an_inline_module_loads_from_that_modules_directory",
            "an_include_macro_in_a_package_source_is_refused",
            "a_file_declared_only_from_another_directory_is_refused",
            "an_included_file_is_classified_through_its_chain_to_the_crate_root",
            "a_scoped_file_that_loads_other_source_is_refused",
            "an_include_outside_the_repository_is_refused",
            "a_parent_that_declares_a_file_by_path_makes_it_production",
            "a_path_attribute_the_include_scanner_misses_is_refused",
            "a_directory_module_is_classified_by_its_parent",
            "an_include_no_module_file_declares_is_refused",
            "a_crate_root_or_another_directory_declares_an_include",
        ],
    ),
    (
        "reference",
        &[
            "an_unknown_binding_is_refused",
            "a_binding_of_another_file_is_refused",
            "a_binding_of_another_operation_in_the_same_file_is_refused",
            "a_twin_that_is_no_control_is_refused",
            "two_twins_in_one_lane_are_refused",
            "a_kill_row_naming_a_loom_control_is_refused",
            "an_entry_naming_a_violation_case_or_a_control_is_refused",
            "a_control_also_listed_under_tests_is_no_positive_test",
            "a_refused_path_or_test_is_never_read",
            "a_loom_failure_in_no_string_literal_is_refused",
            "a_loom_failure_only_an_attribute_holds_is_refused",
            "a_loom_failure_two_message_literals_hold_is_refused",
            "a_loom_failure_another_message_literal_extends_is_refused",
            "a_loom_test_whose_model_source_cannot_be_read_is_refused",
            "a_genmc_failure_that_is_no_one_check_message_is_refused",
            "a_genmc_failure_spelled_c_only_in_a_comment_is_refused",
        ],
    ),
    (
        "disposition",
        &[
            "a_row_with_two_dispositions_or_none_is_refused",
            "a_survives_row_with_an_empty_reason_is_refused",
            "a_disposition_entry_without_its_fields_is_refused",
            "a_disposition_that_names_no_run_is_refused_outside_the_unmodeled_rows",
        ],
    ),
    (
        "enclosing item",
        &[
            "a_find_moved_out_of_its_enclosing_item_is_refused",
            "a_scope_that_resolves_to_two_bodies_is_refused",
            "a_row_without_an_enclosing_item_is_refused",
            "a_find_moved_into_a_nested_item_is_refused",
            "a_binding_of_another_operation_in_the_same_file_is_refused",
        ],
    ),
    ("revision", &["a_decided_row_without_a_revision_is_refused"]),
    (
        "row",
        &[
            "a_repeated_row_id_is_refused",
            "a_malformed_row_is_refused_by_name",
        ],
    ),
];

/// The bodies of the check's cases, by test name, read from the case file as text: each `fn` that a
/// `#[test]` line precedes, up to the brace that closes its first `{`. The markers and the braces are read
/// from the file with its comments and string literals blanked, so neither inside them counts.
fn bodies(source: &str) -> BTreeMap<String, String> {
    let view = crate::rust_text::code(source);
    let mut found = BTreeMap::new();
    for (marker, _) in view.match_indices("#[test]") {
        let rest = &view[marker + "#[test]".len()..];
        let trimmed = rest.trim_start();
        let Some(after) = trimmed.strip_prefix("fn ") else {
            continue;
        };
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let start = view.len() - trimmed.len();
        let Some(open) = view[start..].find('{').map(|at| start + at) else {
            continue;
        };
        let end = crate::production_text::closing(&view, open).unwrap_or(view.len());
        found.insert(name, source[start..end].to_owned());
    }
    found
}

/// `uncommented` is `text` with its comments taken out and the rest trimmed.
fn uncommented(text: &str) -> String {
    let mut kept = String::new();
    let mut at = 0;
    for (kind, start, end) in crate::rust_text::lexemes(text) {
        if kind == crate::rust_text::Lexeme::Comment {
            kept.push_str(&text[at..start]);
            at = end;
        }
    }
    kept.push_str(&text[at..]);
    kept.trim().to_owned()
}

/// `arguments` is the text of each top-level argument of the call whose `(` stands at `open` in
/// `source`, with its brackets and commas read from `view`, `source` with its comments and string
/// literals blanked at the same offsets.
fn arguments<'s>(source: &'s str, view: &str, open: usize) -> Vec<&'s str> {
    let mut depth = 0usize;
    let mut start = open + 1;
    let mut found = Vec::new();
    for (at, byte) in view.bytes().enumerate().skip(open) {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    found.push(source[start..at].trim());
                    return found;
                }
            }
            b',' if depth == 1 => {
                found.push(source[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    found
}

/// `plants` holds where `body`'s code, its comments and string literals passed over, calls one of the
/// check cases' refusing helpers with `refusal` as the argument that names the refusal: `refused(` and
/// `refused_at(`, which assert exit 1, no credit and the refusal; `sentence(`, which asserts the refusal
/// with its whole message, which the check gives only with exit 1 and no credit; `refused_in(`, which is
/// `refused_at(` of `scope file`; or `messages_of(` in a body that also asserts exit 1 and no credit.
fn plants(body: &str, refusal: &str) -> bool {
    let literal = format!("\"{refusal}\"");
    let view = crate::rust_text::code(body);
    let calls = |helper: &str| {
        view.match_indices(helper)
            .filter(|(at, _)| {
                view[..*at]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
            })
            .map(|(at, _)| at + helper.len() - 1)
            .collect::<Vec<_>>()
    };
    let called = |helper: &str, name_at: usize| {
        calls(helper).into_iter().any(|open| {
            arguments(body, &view, open)
                .get(name_at)
                .is_some_and(|argument| uncommented(argument) == literal)
        })
    };
    let asserted = view.contains("assert_eq!(code, 1") && view.contains("Value::Bool(false)");
    called("refused(", 1)
        || called("refused_at(", 2)
        || called("sentence(", 1)
        || (refusal == "scope file" && !calls("refused_in(").is_empty())
        || (asserted && called("messages_of(", 1))
}

/// The help lists exactly the refusals the table names, and each named case of the check exists and
/// plants its refusal through one of the check cases' refusing helpers.
#[test]
fn every_documented_refusal_names_the_tests_that_plant_it() {
    let documented = documented(include_str!("help.md"));
    let named: BTreeSet<String> = CLAUSES.iter().map(|(name, _)| (*name).to_owned()).collect();
    assert_eq!(documented, named);
    let cases = bodies(include_str!("../../orderings/check_tests.rs"));
    for (refusal, tests) in CLAUSES {
        for test in tests {
            let body = cases
                .get(*test)
                .unwrap_or_else(|| panic!("{test} names no test"));
            assert!(plants(body, refusal), "{test} plants {refusal:?}");
        }
    }
    assert!(
        !plants("accepted(plants, \"row\", \"x\");", "row"),
        "a helper outside the list plants nothing"
    );
    assert!(
        !plants("messages_of(&report, \"row\");", "row"),
        "a read with no assertion of the exit plants nothing"
    );
    assert!(plants("sentence(plants, \"row\", \"x\");", "row"));
    assert!(plants("refused_in(plants, \"x.rs\");", "scope file"));
    assert!(
        !plants("// refused(plants, \"row\", \"x\");", "row"),
        "a call in a comment plants nothing"
    );
    assert!(
        !plants("refused(plants, \"find\", \"row\");", "row"),
        "a refusal's name in the message argument plants nothing"
    );
    assert!(plants("refused_at(root, plants, \"row\", \"x\");", "row"));
    assert!(
        !plants("not_refused_in(plants, \"x.rs\");", "scope file"),
        "a call of another helper whose name ends in refused_in plants nothing"
    );
    assert!(
        !plants("refused(plants, \"row\");", "find"),
        "another refusal is not this one"
    );
    assert!(
        !plants("refused(plants, /* \"row\", */ \"find\", \"x\");", "row"),
        "a refusal's name in a comment inside the call plants nothing"
    );
    assert!(plants(
        "refused(plants, /* \"row\", */ \"find\", \"x\");",
        "find"
    ));
    let commented = "/*\n#[test]\nfn hidden() { refused(plants, \"row\", \"x\"); }\n*/\n";
    assert!(
        bodies(commented).is_empty(),
        "a test in a block comment is no test"
    );
    let raw = "#[test]\nfn live() {\n    let s = r##\"#[test]\nfn ghost() {\"##;\n    \
               refused(plants, \"row\", \"x\");\n}\nfn helper() { refused(plants, \"find\", \"x\"); }\n";
    let found = bodies(raw);
    assert_eq!(found.keys().collect::<Vec<_>>(), ["live"]);
    assert!(plants(&found["live"], "row"), "{found:?}");
    assert!(
        !plants(&found["live"], "find"),
        "a helper after the test is no part of it"
    );
}
