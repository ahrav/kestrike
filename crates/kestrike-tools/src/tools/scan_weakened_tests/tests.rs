use super::digits::{integer, is_digits};
use super::hunks::{Hunk, hunks, paired, text_of};
use super::inventory::inventory_changes;
use super::patterns::*;
use super::{Failure, Shown};

type Cases = &'static [(
    &'static str,
    &'static [(&'static str, Option<&'static str>)],
)];

fn check(pattern: &Pattern, group: &str, cases: Cases) {
    for (text, expected) in cases {
        let found: Vec<(&str, Option<&str>)> = pattern
            .captures(text.as_bytes())
            .map(|found| {
                let whole = text_of(found.get(0).expect("group 0 is the match"));
                let value = if group == "1" {
                    found.get(1)
                } else {
                    found.name(group)
                };
                (whole, value.map(text_of))
            })
            .collect();
        assert_eq!(found, *expected, "{text:?}");
    }
}

#[test]
fn the_preemption_bound_pattern_matches_the_inputs_of_the_scan() {
    check(
        &PREEMPTION_BOUND,
        "value",
        &[
            (
                "    builder.preemption_bound = Some(3);",
                &[("preemption_bound = Some(3)", Some("3"))],
            ),
            (
                "    b.preemption_bound = Some(3 /* x */);",
                &[("preemption_bound = Some(3 /* x */)", Some("3"))],
            ),
            (
                "    builder.preemption_bound = Some(PREEMPTION_BOUND);",
                &[],
            ),
            (
                "x.preemption_bound=Some( 1_0 )",
                &[("preemption_bound=Some( 1_0 )", Some("1_0"))],
            ),
        ],
    );
}

#[test]
fn the_max_branches_pattern_matches_the_inputs_of_the_scan() {
    check(
        &MAX_BRANCHES,
        "value",
        &[
            (
                "    builder.max_branches = 10_000;",
                &[("max_branches = 10_000", Some("10_000"))],
            ),
            (
                "    b.max_branches = 10 /* cap */;",
                &[("max_branches = 10", Some("10"))],
            ),
            ("    max_branches = 5_000 * 4;", &[]),
            ("f(max_branches = 7, 2)", &[("max_branches = 7", Some("7"))]),
            ("max_branches = 9x;", &[]),
        ],
    );
}

#[test]
fn the_const_budget_pattern_matches_the_inputs_of_the_scan() {
    check(
        &CONST_BUDGET,
        "value",
        &[
            (
                "const SEEDS: u64 = 48;",
                &[("const SEEDS: u64 = 48", Some("48"))],
            ),
            (
                "const ROOTS: [u64; 3] = [1, 2, 3];",
                &[("const ROOTS: [u64; 3", Some("3"))],
            ),
            (
                "const MOD_ROOTS: [&str; 4] = [\"a\", \"b\", \"c\", \"d\"];",
                &[],
            ),
            (
                "const S19_ROOTS: [u32; 3] = [",
                &[("const S19_ROOTS: [u32; 3", Some("3"))],
            ),
            (
                "const PREEMPTION_BOUND: usize = 9;",
                &[("const PREEMPTION_BOUND: usize = 9", Some("9"))],
            ),
            ("const SEEDS: u64 = 0x40;", &[]),
            (
                "const SEEDS: u64 = 48 /* x */ ;",
                &[("const SEEDS: u64 = 48", Some("48"))],
            ),
        ],
    );
}

#[test]
fn the_named_bound_pattern_matches_the_inputs_of_the_scan() {
    check(
        &NAMED_BOUND,
        "value",
        &[
            (
                "    builder.preemption_bound = Some(PREEMPTION_BOUND);",
                &[("preemption_bound = Some(PREEMPTION_BOUND", None)],
            ),
            (
                "    builder.preemption_bound = Some(bound);",
                &[("preemption_bound = Some(bound", None)],
            ),
            (
                "preemption_bound = Some(LOW) ;",
                &[("preemption_bound = Some(LOW", None)],
            ),
            ("preemption_bound = Some(LOW + 1)", &[]),
            ("preemption_bound = Some(3)", &[]),
        ],
    );
}

#[test]
fn the_reason_pattern_matches_the_inputs_of_the_scan() {
    check(
        &REASON,
        "value",
        &[
            ("#[ignore = \"slow\"]", &[("ignore = \"slow\"", None)]),
            (
                concat!(
                    "#[cfg_attr(miri, ",
                    "ignore = \"a \\\"quoted\\\" ] reason\")]"
                ),
                &[("ignore = \"a \\\"quoted\\\" ] reason\"", None)],
            ),
            (concat!("#[cfg_attr(miri, ", "ignore)]"), &[]),
        ],
    );
}

#[test]
fn the_timeout_minutes_pattern_matches_the_inputs_of_the_scan() {
    check(
        &TIMEOUT_MINUTES,
        "value",
        &[
            (
                "    timeout-minutes: 15",
                &[("timeout-minutes: 15", Some("15"))],
            ),
            (
                "    timeout-minutes: 15 # fifteen",
                &[("timeout-minutes: 15", Some("15"))],
            ),
            ("timeout-minutes:20", &[("timeout-minutes:20", Some("20"))]),
        ],
    );
}

#[test]
fn the_deadline_pattern_matches_the_inputs_of_the_scan() {
    check(
        &DEADLINE,
        "value",
        &[
            (
                "  step check deadline 25m cargo check",
                &[("deadline 25m", Some("25"))],
            ),
            ("deadline 5ms", &[]),
            ("deadline  30m", &[("deadline  30m", Some("30"))]),
        ],
    );
}

#[test]
fn the_timeout_pattern_matches_the_inputs_of_the_scan() {
    check(
        &TIMEOUT,
        "value",
        &[
            (
                "    run: exec timeout --kill-after=30s 5m make",
                &[("timeout --kill-after=30s 5m", Some("5"))],
            ),
            ("timeout 5m", &[("timeout 5m", Some("5"))]),
            (
                "timeout --kill-after=30s 7m 9m",
                &[("timeout --kill-after=30s 7m", Some("7"))],
            ),
        ],
    );
}

#[test]
fn the_inventory_text_budget_pattern_matches_the_inputs_of_the_scan() {
    check(
        &INVENTORY_TEXT_BUDGET,
        "value",
        &[
            (
                "^a: depth: 6 actions 40$",
                &[("depth: 6", Some("6")), ("actions 40", Some("40"))],
            ),
            ("^f: cycles 9$", &[("cycles 9", Some("9"))]),
            ("^a: depth: 6 actions 40?$", &[("depth: 6", Some("6"))]),
            (
                "^a: depth: 5[0-9] actions 40$",
                &[("actions 40", Some("40"))],
            ),
            (
                "^a: depth: 3 depth: 5$",
                &[("depth: 3", Some("3")), ("depth: 5", Some("5"))],
            ),
            ("depth: 4", &[("depth: 4", Some("4"))]),
        ],
    );
}

#[test]
fn the_assert_pattern_matches_the_inputs_of_the_scan() {
    check(
        &ASSERT,
        "value",
        &[
            ("    assert!(true);", &[("assert!", None)]),
            ("    assert_eq!(1, 1);", &[("assert_eq!", None)]),
            ("debug_assert!(x)", &[]),
            ("reassert!(x)", &[]),
        ],
    );
}

#[test]
fn the_digits_pattern_matches_the_inputs_of_the_scan() {
    check(
        &DIGITS,
        "value",
        &[
            ("Some(10_000)", &[("10_000", None)]),
            ("x9_y", &[("9_", None)]),
            ("٣٤_1", &[("٣٤_1", None)]),
        ],
    );
}

#[test]
fn the_hunk_pattern_matches_the_inputs_of_the_scan() {
    check(
        &HUNK,
        "1",
        &[
            ("@@ -1 +1 @@", &[("@@ -1 +1 @@", Some("1"))]),
            ("@@ -3,2 +4,0 @@ fn f()", &[("@@ -3,2 +4,0 @@", Some("4"))]),
            ("@@ -1 +1,2 @@", &[("@@ -1 +1,2 @@", Some("1"))]),
            (" @@ -1 +1 @@", &[]),
        ],
    );
}

#[test]
fn the_aliasing_pattern_matches_the_inputs_of_the_scan() {
    check(
        &ALIASING,
        "value",
        &[
            ("qualified.lane", &[(".", None)]),
            ("rows[b]", &[("[", None), ("]", None)]),
            ("plain", &[]),
        ],
    );
}

#[test]
fn the_scope_pattern_matches_the_inputs_of_the_scan() {
    check(
        &SCOPE,
        "value",
        &[
            (
                "mod a {\nfn x() {}\n}",
                &[("mod a {", None), ("{", None), ("}", None), ("}", None)],
            ),
            ("mod r#kind {\n}", &[("mod r#kind {", None), ("}", None)]),
            ("impl H {\n}", &[("{", None), ("}", None)]),
            ("mod tests;", &[]),
        ],
    );
}

#[test]
fn a_digit_outside_ascii_counts_by_its_offset_in_its_run_modulo_ten() {
    let read = |digits: &str| integer(digits).expect("the digits read").to_string();
    assert_eq!(read("10_000"), "10000");
    assert_eq!(read("\u{663}\u{664}_1"), "341");
    assert_eq!(read("\u{1d7ce}\u{1d7d9}\u{1d7e2}"), "10");
    assert_eq!(read("\u{ff19}\u{966}"), "90");
}

#[test]
fn a_run_of_more_than_4300_digits_refuses_and_4300_reads() {
    assert!(integer(&"1".repeat(4300)).is_ok());
    let error = integer(&format!("{}_1", "0".repeat(4300))).expect_err("the run passes the limit");
    assert!(matches!(error, Failure::Digits(4301)), "{error:?}");
}

#[test]
fn an_id_is_digits_by_the_decimal_and_other_digit_code_points() {
    let digits = |text: &str| is_digits(text.chars().map(u32::from));
    assert!(digits("1") && digits("\u{663}") && digits("\u{b2}") && digits("\u{2460}\u{1f10a}"));
    assert!(!digits("") && !digits("1a") && !digits("\u{bc}") && !digits("\u{2469}"));
}

#[test]
fn a_diff_yields_each_hunk_with_its_removed_lines_and_numbered_added_lines() {
    let lines = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n-a\n+b\n+c\n@@ -5 +6 @@\n-d\n\\ end\n";
    let found = hunks(lines.split('\n')).expect("the diff reads");
    let hunk = |removed: &[&str], added: &[(u64, &str)]| Hunk {
        removed: removed.iter().map(|text| (*text).to_owned()).collect(),
        added: added
            .iter()
            .map(|&(number, text)| (number, text.to_owned()))
            .collect(),
    };
    assert_eq!(
        found,
        [hunk(&["a"], &[(1, "b"), (2, "c")]), hunk(&["d"], &[])]
    );
}

#[test]
fn a_new_item_pairs_with_the_earliest_unpaired_old_item_of_its_key() {
    let (pairs, unpaired) = paired(
        [("k", 1), ("j", 2), ("k", 3), ("k", 4)],
        [("k", 10), ("m", 11), ("k", 12)],
    );
    assert_eq!(pairs, [(1, 10), (3, 12)]);
    assert_eq!(unpaired, [("k", 4), ("j", 2)]);
}

#[test]
fn an_inventory_reports_falls_absences_and_rises_in_document_order() {
    let old = r#"{"rows": [{"id": "a", "seeds": 5, "bound": "depth: 4 cycles 2"}], "deadline_seconds": 3}"#;
    let new = r#"{"rows": [{"id": "a", "seeds": 4, "bound": "depth: 5"}], "deadline_seconds": 9}"#;
    let found: Vec<(String, String)> = inventory_changes(old, new)
        .expect("the inventories compare")
        .into_iter()
        .map(|(kind, name, old, new)| (format!("{kind} {name}"), format!("{old} -> {new}")))
        .collect();
    let row = |kind: &str, name: &str, values: &str| (format!("{kind} {name}"), values.to_owned());
    assert_eq!(
        found,
        [
            row("budget-lowered", "rows[a].seeds", "5 -> 4"),
            row("budget-lowered", "rows[a].bound cycles", "2 -> absent"),
            row("timeout-raised", "deadline_seconds", "3 -> 9"),
        ]
    );
    assert_eq!(Shown::absent().to_string(), "absent");
}

#[test]
fn a_boolean_or_a_float_is_no_inventory_count() {
    let old = r#"{"seeds": true, "seconds": 2.0, "executions": 3}"#;
    let new = r#"{"seeds": false, "seconds": 1.0, "executions": 2.5}"#;
    assert!(
        inventory_changes(old, new)
            .expect("the inventories compare")
            .is_empty()
    );
}

#[test]
fn duplicate_keys_keep_the_last_value_at_the_first_place() {
    let old = r#"{"seeds": 1, "seconds": 9, "seeds": 7}"#;
    let new = r#"{"seconds": 8, "seeds": 6}"#;
    let found: Vec<String> = inventory_changes(old, new)
        .expect("the inventories compare")
        .into_iter()
        .map(|(_, name, old, new)| format!("{name}: {old} -> {new}"))
        .collect();
    assert_eq!(found, ["seeds: 7 -> 6", "seconds: 9 -> 8"]);
}
