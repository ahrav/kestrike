//! Traces of the attach-gate model, `quint/gate.qnt`, for the replay against `Volume`.
//!
//! A directed trace follows one recipe; a seeded trace takes [`STEPS`] steps of the model's own `step`
//! under the seed its name carries. Every trace records under `#meta.gate` the model's digest, its seed,
//! its number of steps and a directed trace's recipe, and the replay refuses a trace whose digest differs
//! from the model's.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::fixtures::{self, Model, Style, Trace, case};

pub const NAME: &str = "gate_fixtures";

pub(crate) const MODEL: Model = Model {
    tool: NAME,
    about: "Attach-gate model traces for the replay against `Volume`: the directed recipes and seeded runs of `step`.",
    name: "gate",
    style: Style::Format,
    limit: Duration::from_secs(120),
};

pub const STEPS: usize = 12;
const RECIPE_SEED: u64 = 0x1220;
pub const SEEDS: [u64; 8] = [
    0x1221, 0x1222, 0x1223, 0x1224, 0x1225, 0x1226, 0x1227, 0x1228,
];

pub const SUBMIT: &str = "tick(\"none\")";

macro_rules! reported {
    ($($action:expr),*) => {
        &[SUBMIT, "register(true)", SUBMIT, "acquire(true)", SUBMIT, $($action),*]
    };
}

pub const REPORTED: &[&str] = reported!();

/// The first four recipes equal `RUNS` of `quint/gate_check.py`, and [`SUBMIT`] and [`REPORTED`] equal its
/// `SUBMIT` and `REPORTED`; `quint/check.py` runs those recipes as checked runs.
#[rustfmt::skip]
pub const RECIPES: [(&str, &[&str]); 18] = [
    ("passes", reported!["report(\"sole\")", SUBMIT]),
    ("busy_then_foreign_registrant", &[
        "tick(\"busy\")", SUBMIT, "register(true)", SUBMIT, "acquire(true)", SUBMIT, "report(\"registrant\")", SUBMIT,
    ]),
    ("acquire_conflict", &[SUBMIT, "register(true)", SUBMIT, "acquire(false)", SUBMIT]),
    ("report_times_out", reported!["timeout", SUBMIT]),
    ("register_conflict", &[SUBMIT, "register(false)", SUBMIT]),
    ("submit_refused", &[SUBMIT, "register(true)", "tick(\"busy\")", "tick(\"invalid\")", SUBMIT]),
    ("device_gone", &[SUBMIT, "register(true)", SUBMIT, "acquire(true)", "tick(\"gone\")", SUBMIT]),
    ("foreign_holder", reported!["report(\"holder\")", SUBMIT]),
    ("other_type", reported!["report(\"type\")", SUBMIT]),
    ("duplicate_own_record", reported!["report(\"duplicate\")", SUBMIT]),
    ("own_pair_not_holding", reported!["report(\"notholder\")", SUBMIT]),
    ("withheld_bytes", reported!["report(\"withheld\")", SUBMIT]),
    ("failed_report", reported!["report(\"failed\")", SUBMIT]),
    ("deposing_report", reported!["report(\"deposing\")", SUBMIT]),
    ("expiry_under_the_register", &[SUBMIT, "expire", SUBMIT]),
    ("withdrawal_under_the_acquire", &[SUBMIT, "register(true)", SUBMIT, "withdraw", SUBMIT]),
    ("close_under_the_report", reported!["close", SUBMIT]),
    ("close_before_the_register", &["close", SUBMIT]),
];

pub fn run(top: &Path, args: &[OsString]) -> u8 {
    let directed = RECIPES
        .iter()
        .map(|&(name, recipe)| trace(name.to_owned(), RECIPE_SEED, Some(recipe)));
    let seeded = SEEDS
        .iter()
        .map(|&seed| trace(format!("step_{seed:x}"), seed, None));
    let traces: Vec<Trace> = directed.chain(seeded).collect();
    fixtures::write(&MODEL, top, args, &traces, fixtures::keep)
}

fn trace(name: String, seed: u64, recipe: Option<&'static [&'static str]>) -> Trace {
    Trace::new(name, seed, recipe, STEPS, case::gate, Vec::new())
}
