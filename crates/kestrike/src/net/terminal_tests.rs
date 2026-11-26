//! The terminal identity catalog: for every counter that issues an identity
//! (the retirement era, the fill serial, the index sequence, the slot
//! incarnation, the command generation, the request and wire generations,
//! the buffer incarnation and the session counters) the probes that plant
//! its bound and check its last issuance, its exact refusal or quarantine,
//! that no identity repeats, that a stale token changes nothing and that
//! the old rights drain and clean up lawfully, plus the probes that show a
//! clock jump advances time and no counter.
//!
//! Each probe carries a width label. An `Actual` probe plants the
//! production bound at its real width; an `Accelerated` probe runs a
//! reduced limit and provides evidence specific to that limit. Every probe
//! is a required test of the ordinary selection, cited by the obligation
//! catalog or named as an inventory anchor, so the selection validator
//! fails a lane that drops or skips one.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use serde_json::Value;

/// The committed test inventory, decoded.
pub(crate) static INVENTORY: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../../scripts/test-inventory.json"))
        .expect("the inventory parses")
});

/// The committed obligation catalog, decoded.
pub(crate) static OBLIGATIONS: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../../verification/obligations.json"))
        .expect("the catalog parses")
});

/// The test IDs of `array`; panics naming `what` when `array` is no array
/// of strings.
fn test_ids<'v>(array: &'v Value, what: &str) -> impl Iterator<Item = &'v str> {
    array
        .as_array()
        .unwrap_or_else(|| panic!("{what} is an array"))
        .iter()
        .map(move |test| {
            test.as_str()
                .unwrap_or_else(|| panic!("{what} holds test IDs"))
        })
}

/// The catalog's records.
fn records(obligations: &Value) -> &[Value] {
    obligations["records"]
        .as_array()
        .expect("the catalog's records")
}

/// Every test the catalog's workspace records cite: each record's `tests`
/// and the `test` of each of its controls. The selector derives the
/// required workspace controls from exactly these fields.
pub(crate) fn workspace_tests(obligations: &Value) -> BTreeSet<&str> {
    let mut cited = BTreeSet::new();
    for record in records(obligations)
        .iter()
        .filter(|record| record["job"] == "workspace")
    {
        cited.extend(test_ids(&record["tests"], "a record's tests"));
        for control in record["controls"].as_array().expect("a record's controls") {
            cited.insert(control["test"].as_str().expect("a control's test"));
        }
    }
    cited
}

/// The one catalog record whose `id` is `id`.
fn record<'o>(obligations: &'o Value, id: &str) -> &'o Value {
    let mut matching = records(obligations)
        .iter()
        .filter(|record| record["id"] == id);
    let record = matching
        .next()
        .unwrap_or_else(|| panic!("the record {id} is missing"));
    assert!(matching.next().is_none(), "the record {id} is listed twice");
    record
}

/// The `tests` of the one catalog record whose `id` is `id`.
pub(crate) fn record_tests<'o>(obligations: &'o Value, id: &str) -> BTreeSet<&'o str> {
    test_ids(&record(obligations, id)["tests"], "the record's tests").collect()
}

/// The `(test, violation)` pairs of the controls of the one catalog record
/// whose `id` is `id`.
pub(crate) fn record_controls<'o>(
    obligations: &'o Value,
    id: &str,
) -> BTreeSet<(&'o str, &'o str)> {
    record(obligations, id)["controls"]
        .as_array()
        .expect("the record's controls")
        .iter()
        .map(|control| {
            let field = |name: &str| control[name].as_str().expect("a control's text field");
            (field("test"), field("violation"))
        })
        .collect()
}

/// The tests the inventory's `kestrike` witness lists by name. The
/// selector refuses a listed test that a workspace record also cites.
pub(crate) fn anchors(inventory: &Value) -> BTreeSet<&str> {
    test_ids(
        &inventory["ordinary"]["kestrike"]["required"]["kestrike"]["tests"],
        "the crate's witness tests",
    )
    .collect()
}

/// Each reader takes a record's fields from that record alone, whatever
/// the field order or spacing, and a bracket inside a violation ends no
/// control list.
#[test]
fn the_catalog_readers_take_each_record_by_its_own_fields() {
    let catalog: Value = serde_json::from_str(
        r#"{"records":[
        {"tests":["a::one"],"id":"first","job":"workspace","controls":[{"violation":"x [y]","test":"a::control"}]},
        {"id": "second", "job": "loom", "tests": ["a::two"], "controls": [{"test": "a::loom", "violation": "z"}]},
        {"id":"third","job":"workspace","tests":["a::three"],"controls":[]}]}"#,
    )
    .unwrap();
    assert_eq!(
        workspace_tests(&catalog),
        BTreeSet::from(["a::one", "a::control", "a::three"])
    );
    assert_eq!(record_tests(&catalog, "second"), BTreeSet::from(["a::two"]));
    assert_eq!(
        record_tests(&catalog, "third"),
        BTreeSet::from(["a::three"])
    );
    assert_eq!(
        record_controls(&catalog, "first"),
        BTreeSet::from([("a::control", "x [y]")])
    );
    assert_eq!(record_controls(&catalog, "third"), BTreeSet::new());
}

/// Whether a probe plants the production bound or a smaller limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Width {
    Actual,
    Accelerated,
}

/// Every counter family the catalog must cover with an actual-width probe.
const FAMILIES: [&str; 10] = [
    "retirement era at ERA_TERMINAL",
    "fill serial at SERIAL_MAX",
    "index sequence at TERMINAL",
    "slot incarnation at u32::MAX",
    "command generation at 48 bits",
    "request generation at 48 bits",
    "release board wire generation at 48 bits",
    "buffer incarnation at u64::MAX",
    "session counters at u64::MAX",
    "clock jump advances no counter",
];

/// The probes: family, width label and the test that runs it.
const CATALOG: [(&str, Width, &str); 22] = [
    (
        FAMILIES[0],
        Width::Actual,
        "storage::grace_tests::the_terminal_era_poisons_admission_and_keeps_existing_pins_and_leases",
    ),
    (
        FAMILIES[1],
        Width::Actual,
        "storage::attempt_tests::a_planted_serial_maximum_exhausts_issuance_permanently_but_not_cleanup",
    ),
    (
        FAMILIES[2],
        Width::Actual,
        "storage::publish_tests::the_terminal_sequence_stops_one_shard_and_a_poisoned_gate_refuses",
    ),
    (
        FAMILIES[2],
        Width::Actual,
        "storage::publication_tests::a_full_lease_limit_and_a_terminal_shard_refuse_at_reservation_before_any_upload",
    ),
    (
        FAMILIES[2],
        Width::Actual,
        "storage::remove_tests::a_terminal_shard_still_ends_mappings",
    ),
    (
        FAMILIES[3],
        Width::Actual,
        "storage::retire_tests::exhausted_incarnation_through_full_cycles_quarantines_the_slot",
    ),
    (
        FAMILIES[3],
        Width::Actual,
        "storage::reserve::tests::exhausted_incarnation_quarantines_the_slot_and_stale_identities_are_rejected",
    ),
    (
        FAMILIES[3],
        Width::Actual,
        "storage::policy_tests::reuse_links_once_and_an_exhausted_incarnation_never_links",
    ),
    (
        FAMILIES[4],
        Width::Actual,
        "storage::device::table_tests::a_slot_at_the_maximum_generation_retires_and_all_retired_is_table_full",
    ),
    (
        FAMILIES[5],
        Width::Actual,
        "net::memory_tests::a_slot_at_the_actual_generation_limit_issues_it_last_drains_and_retires",
    ),
    (
        FAMILIES[5],
        Width::Actual,
        "net::serve_tests::generations_end_in_counter_exhaustion_and_older_ones_drop",
    ),
    (
        FAMILIES[5],
        Width::Accelerated,
        "net::memory_tests::released_handles_go_stale_and_an_exhausted_slot_retires",
    ),
    (
        FAMILIES[5],
        Width::Actual,
        "net::put_tests::typed_refusals_precede_admission_and_a_wrong_serial_conflicts",
    ),
    (
        FAMILIES[6],
        Width::Actual,
        "net::fetch_tests::a_board_at_its_actual_last_wire_generation_issues_it_once_then_refuses",
    ),
    (
        FAMILIES[6],
        Width::Accelerated,
        "net::fetch_tests::a_board_past_its_last_wire_generation_refuses_fetches",
    ),
    (
        FAMILIES[6],
        Width::Accelerated,
        "net::client_namespace_tests::refused_admissions_keep_the_generation_counter",
    ),
    (
        FAMILIES[7],
        Width::Actual,
        "storage::device::nic_tests::incarnations_retire_before_they_wrap",
    ),
    (
        FAMILIES[7],
        Width::Actual,
        "net::memory_tests::a_retired_buffer_comes_out_of_the_data_cap_not_the_control_reserve",
    ),
    (
        FAMILIES[8],
        Width::Actual,
        "net::auth_tests::counter_exhaustion_retires_without_panic",
    ),
    (
        FAMILIES[8],
        Width::Actual,
        "net::auth_tests::session_counters_issue_their_last_value_once_at_the_actual_width",
    ),
    (
        FAMILIES[9],
        Width::Actual,
        "net::fetch_tests::a_clock_jump_advances_no_wire_generation",
    ),
    (
        FAMILIES[9],
        Width::Actual,
        "storage::lookup_tests::a_clock_jump_expires_by_time_and_advances_no_counter",
    ),
];

const CATALOG_CHECK: &str =
    "net::terminal_tests::every_terminal_family_has_an_actual_width_probe_the_inventory_requires";

/// Every family has an actual-width probe, every probe names a catalogued
/// family and appears once, and every probe is a required test of the
/// ordinary selection: the obligation catalog cites it or the inventory
/// names it as an anchor.
#[test]
fn every_terminal_family_has_an_actual_width_probe_the_inventory_requires() {
    for family in FAMILIES {
        assert!(
            CATALOG
                .iter()
                .any(|&(of, width, _)| of == family && width == Width::Actual),
            "{family} has no actual-width probe"
        );
    }
    let anchors = anchors(&INVENTORY);
    let cited = workspace_tests(&OBLIGATIONS);
    let credited = record_tests(
        &OBLIGATIONS,
        "terminal-identities-issue-last-and-never-repeat",
    );
    let mut seen = BTreeSet::new();
    let mut actual = BTreeSet::from([CATALOG_CHECK]);
    for (family, width, test) in CATALOG {
        assert!(FAMILIES.contains(&family), "{test} names {family}");
        assert!(seen.insert(test), "{test} is catalogued twice");
        assert!(
            anchors.contains(test) || cited.contains(test),
            "{test} ({width:?}) is not a required test"
        );
        if width == Width::Actual {
            actual.insert(test);
        }
    }
    assert_eq!(
        credited, actual,
        "the terminal obligation's tests and the actual-width probes differ"
    );
}
