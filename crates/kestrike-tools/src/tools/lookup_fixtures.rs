use std::ffi::OsString;
use std::path::Path;

use crate::fixtures::{self, Model, Style};

pub(crate) const MODEL: Model = Model {
    tool: "lookup_fixtures",
    about: "Lookup model traces for the replay against `Storage`: the directed recipes and seeded runs of `step`.",
    name: "lookup",
    style: Style::Record,
};

pub const STEPS: usize = 16;
const RECIPE_SEED: u64 = 0x5e00;
#[rustfmt::skip]
pub const SEEDS: [(&str, u64); 6] = [
    ("step_a", 0x5e01), ("step_b", 0x5e02), ("step_c", 0x5e03), ("step_d", 0x5e04), ("step_e", 0x5e05), ("step_f", 0x5e06),
];

#[rustfmt::skip]
pub const RECIPES: [(&str, &[&str]); 4] = [
    ("replaceUnderLease", &[
        "publish(0)", "lookup(0)", "replace(0)", "lookup(0)", "certify", "service", "drop(1)", "service",
    ]),
    ("removeThenReclaim", &["publish(0)", "remove(0)", "lookup(0)", "certify", "service"]),
    ("expiryAndClose", &["publish(0)", "publish(1)", "expire", "lookup(0)", "close", "lookup(1)", "remove(1)"]),
    ("twoKeys", &[
        "service", "certify", "certify", "publish(0)", "publish(1)", "lookup(1)", "remove(0)", "remove(1)", "certify",
        "service", "drop(2)", "service", "lookup(0)",
    ]),
];

pub fn run(top: &Path, args: &[OsString]) -> u8 {
    let traces = fixtures::traces(&MODEL, &RECIPES, RECIPE_SEED, &SEEDS, STEPS);
    fixtures::write(&MODEL, top, args, &traces, fixtures::keep)
}
