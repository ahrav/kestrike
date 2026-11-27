use std::ffi::OsString;
use std::path::Path;

use crate::fixtures::{self, Model, Style};

pub(crate) const MODEL: Model = Model {
    tool: "reclaim_fixtures",
    about: "Reclaim model traces for the replay against `Storage`: the directed recipes and seeded runs of `step`.",
    name: "reclaim",
    style: Style::Record,
};

pub const STEPS: usize = 18;
const RECIPE_SEED: u64 = 0x7c00;
#[rustfmt::skip]
pub const SEEDS: [(&str, u64); 6] = [
    ("step_a", 0x7c01), ("step_b", 0x7c02), ("step_c", 0x7c03), ("step_d", 0x7c04), ("step_e", 0x7c05), ("step_f", 0x7c06),
];

#[rustfmt::skip]
pub const RECIPES: [(&str, &[&str]); 5] = [
    ("anchorLast", &["unlease", "retire", "certify", "certify", "service"]),
    ("rightLast", &["retire", "certify", "certify", "service", "unlease", "service"]),
    ("pinnedReaderHolds", &[
        "enter(0)", "unlease", "retire", "certify", "certify", "service", "exit(0)", "certify", "certify", "service",
    ]),
    ("reuse", &[
        "unlease", "retire", "certify", "certify", "service", "republish", "unlease", "retire", "certify", "certify",
        "service", "republish",
    ]),
    ("leases", &[
        "lease", "unlease", "service", "certify", "certify", "certify", "retire", "enter(1)", "certify", "certify",
        "service", "service", "unlease", "service", "exit(1)",
    ]),
];

pub fn run(top: &Path, args: &[OsString]) -> u8 {
    let traces = fixtures::traces(&MODEL, &RECIPES, RECIPE_SEED, &SEEDS, STEPS);
    fixtures::write(&MODEL, top, args, &traces, fixtures::keep)
}
