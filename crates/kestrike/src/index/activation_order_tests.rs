//! The scan model's activation bracket against the production commit it
//! says it spells out.
//!
//! `scan_model.rs` states that its writer's stores are "spelled out here in
//! the production order". The production order of a pending pair's
//! activation is the order of `storage::publish::store`. The model compiles
//! only under `loom`; both files are read as text, so these tests run in
//! every test build and hold the model's code and its documentation to the
//! order of the production code.

const MODEL: &str = include_str!("scan_model.rs");
const PUBLISH: &str = include_str!("../storage/publish.rs");

/// The text of `source` from `start` up to the first `end` after it.
fn section<'s>(source: &'s str, start: &str, end: &str) -> &'s str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("{start:?} is in the source"));
    let rest = &source[from..];
    let to = rest[start.len()..]
        .find(end)
        .unwrap_or_else(|| panic!("{end:?} follows {start:?}"));
    &rest[..start.len() + to]
}

/// Whether `lane` comes before `summary` in `text`, both present.
fn lane_first(text: &str, lane: &str, summary: &str) -> bool {
    let lane = text
        .find(lane)
        .unwrap_or_else(|| panic!("{lane:?} is in the section"));
    let summary = text
        .find(summary)
        .unwrap_or_else(|| panic!("{summary:?} is in the section"));
    lane < summary
}

/// Whether `publish::store`, the stores of the production commit, activates
/// the pending pair's lane before it stores the chain summary.
fn production_stores_the_lane_first() -> bool {
    let store = section(PUBLISH, "pub(super) fn store(", "\n}\n");
    lane_first(store, ".activate_pair(", "hold.summaries[")
}

/// Joining the module documentation's lines lets a phrase match a sentence
/// the documentation breaks across lines.
fn module_documentation(source: &str) -> String {
    source
        .lines()
        .take_while(|line| line.starts_with("//!"))
        .map(|line| line.trim_start_matches("//!").trim())
        .collect::<Vec<_>>()
        .join(" ")
}

fn states_the_production_order(model: &str) -> bool {
    module_documentation(model)
        .contains("the writer's stores are spelled out here in the production order")
}

#[test]
fn the_models_statement_of_the_production_order_is_found_wherever_its_lines_break() {
    let reflowed = [
        "//! the writer's stores are spelled out here in the",
        "//! production order.",
    ]
    .join("\n");
    assert!(
        states_the_production_order(&reflowed),
        "the sentence stands across the line break of {reflowed:?}"
    );
    assert!(!states_the_production_order(
        "//! the buckets are loom atomics."
    ));
}

/// The `Activate` arm of the model's bracket stores the pending pair's lane
/// and the chain summary in the program order of `publish::store`, as the
/// model's documentation states of every store of its writer. A reader
/// copies the pair only after both stores, since it stops at a chain
/// summary that excludes its key and its scan skips a pending lane, so the
/// order is a property of the model's text, which this test reads.
#[test]
fn the_models_activation_bracket_stores_in_the_production_order() {
    assert!(
        states_the_production_order(MODEL),
        "the model states that it keeps the production order"
    );
    // The bracket's arm of `Mutation::commit`, the one that calls the activation.
    let bracket = section(
        MODEL,
        "let busy = Busy::begin(&shard.sequence, stable);\n        match self {",
        "Self::Cancel => unreachable!",
    );
    let arm = section(bracket, "Self::Activate => {", "\n            }\n");
    let model = lane_first(
        arm,
        "overflow.activate_pair(0)",
        "shard.summaries[1].store(",
    );
    assert_eq!(
        model,
        production_stores_the_lane_first(),
        "the model's activation bracket stores the lane first: {model}; production's commit stores the lane first: {}",
        production_stores_the_lane_first()
    );
}

/// The module documentation's account of `Activate` and the documentation of
/// `Mutation::Activate` each name the lane and the chain summary in the
/// order `publish::store` stores them, the order the module documentation
/// states for every store of the writer.
#[test]
fn the_models_documentation_states_the_production_order_of_an_activation() {
    let module = module_documentation(MODEL);
    let activate = section(
        &module,
        "`Activate` is a pending pair's publication",
        "`Cancel` frees",
    );
    let documented = lane_first(
        activate,
        "the lane that makes the pair occupied",
        "the chain summary",
    );
    assert_eq!(
        documented,
        production_stores_the_lane_first(),
        "the module documentation says of the activation bracket: {activate:?}"
    );
    let variant = section(
        MODEL,
        "/// A pending pair's publication:",
        "\n    Activate,",
    );
    let variant: String = variant
        .lines()
        .map(|line| line.trim().trim_start_matches("///").trim())
        .collect::<Vec<_>>()
        .join(" ");
    let documented = lane_first(&variant, "the occupied lane", "chain summary");
    assert_eq!(
        documented,
        production_stores_the_lane_first(),
        "the documentation of Mutation::Activate says: {variant:?}"
    );
}
