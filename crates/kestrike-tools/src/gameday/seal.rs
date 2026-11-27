//! `injection/collected.json` must name every collected file, `coverage.json`, and every present mark
//! except a restoration whose time ends no observation, must name only files that stand, and must hold
//! the SHA-256 of every collected file, every sealed mark, and `coverage.json`.

use std::collections::{BTreeMap, BTreeSet};

use super::constants::MARKS;
use super::order::ends_observation;
use super::refusal::{Refusal, need, said};
use super::schema::{checked_field, checked_object, checked_text};
use crate::json::{Object, Value};
use crate::python::{hexdigest, repr};
use crate::text::Text;

const RESTORATION: &str = "injection/restoration.json";

/// `observed` identifies the collected files in `files`; `values` holds each file parsed. A restoration
/// that ends no observation ([`ends_observation`]) may stand unsealed, since the restore may run after
/// the seal.
///
/// # Errors
///
/// `check_seal` returns the first refusal, in this order: for each collected file and `coverage.json`
/// in sorted order, `injection/collected.json seals no <rel>`; for each sealed name in sorted order,
/// `injection/collected.json seals <rel>, which is missing`; for each unsealed mark in the layout's
/// order, a refusal unless it is a restoration that ends no observation; then for each collected file
/// in sorted order, each sealed mark in the layout's order and `coverage.json`,
/// `<rel> differs from the bytes injection/collected.json seals: it holds SHA-256 <held>, the seal
/// <digest>`.
///
/// # Panics
///
/// `check_seal` panics if `values` lacks `injection/collected.json` or if it reaches a present,
/// unsealed `injection/restoration.json` that `values` lacks.
pub(super) fn check_seal(
    p: &Object,
    values: &BTreeMap<Text, Value>,
    files: &BTreeMap<Text, Vec<u8>>,
    observed: &BTreeSet<Text>,
) -> Result<(), Refusal> {
    let coverage = Text::from("coverage.json");
    let seal = values
        .get(&Text::from("injection/collected.json"))
        .expect("the layout requires the seal");
    let bound: BTreeMap<&Text, &Value> = checked_object(checked_field(seal, "files"))
        .iter()
        .map(|(key, digest)| (key, digest))
        .collect();
    let named = |rel: &Text| bound.contains_key(rel);
    let spanned: BTreeSet<&Text> = observed.iter().chain([&coverage]).collect();
    for rel in spanned {
        need(named(rel), || {
            said!("injection/collected.json seals no ", rel)
        })?;
    }
    for rel in bound.keys() {
        need(files.contains_key(*rel), || {
            said!("injection/collected.json seals ", rel, ", which is missing")
        })?;
    }
    for mark in MARKS {
        let rel = Text::from(mark);
        if !files.contains_key(&rel) || named(&rel) {
            continue;
        }
        need(mark == RESTORATION, || {
            said!(
                rel,
                " stands unsealed, and only a restoration may: the seal names each mark that stands \
                 when it is written"
            )
        })?;
        let restoration = values.get(&rel).expect("a mark that stands is parsed");
        let at = checked_field(restoration, "time");
        need(!ends_observation(p, Some(at)), || {
            let end = checked_field(
                p.get("run").expect("the package names its run window"),
                "end",
            );
            said!(
                rel,
                " stands unsealed and dates ",
                repr(at),
                ", less than the clock error after the run window's end ",
                repr(end),
                ", so it may end observation",
            )
        })?;
    }
    let marks = MARKS.iter().map(|mark| Text::from(*mark));
    let compared = observed
        .iter()
        .cloned()
        .chain(marks.filter(named))
        .chain([coverage]);
    for rel in compared {
        let held = hexdigest(files.get(&rel).expect("each compared file stands"));
        let digest = checked_text(bound.get(&rel).expect("each compared file is sealed"));
        need(*digest == held.as_str(), || {
            said!(
                rel,
                " differs from the bytes injection/collected.json seals: it holds SHA-256 ",
                held,
                ", the seal ",
                digest,
            )
        })?;
    }
    Ok(())
}
