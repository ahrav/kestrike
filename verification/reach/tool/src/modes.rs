//! Invariant: `measure` assigns a placement state to every variant of
//! `family` and retains all earlier reason rows. Rows follow the order
//! `Source::listed` gives, each enum's variants in declaration order.

use std::collections::{BTreeMap, BTreeSet};

use crate::coverage::Coverage;
use crate::mapping::{self, Measured, State};
use crate::register::{Live, Reason, Register, Row, Run, Totals};
use crate::source::{Site, Source};

fn triples(sites: &[&Site]) -> Vec<(String, String, String)> {
    sites
        .iter()
        .map(|site| {
            (
                site.file.clone(),
                site.function.clone(),
                site.form.name().to_owned(),
            )
        })
        .collect()
}

fn variants<'a>(source: &'a Source, family: &str) -> Vec<(String, String, Vec<&'a Site>)> {
    let mut found = Vec::new();
    for owner in source.listed(family) {
        let declared = &source.enums[owner];
        for variant in &declared.variants {
            let sites = source.sites_of(owner, &variant.name).collect();
            found.push((declared.path.clone(), variant.name.clone(), sites));
        }
    }
    found
}

/// `group` builds each reason id from the measured name and a grouping key:
/// the set of read-site files for `FileNotRun` and `FunctionNotEntered`, or
/// `enum_path` for `NotConstructed`.
fn group(enum_path: &str, sites: &[&Site], measured: Measured) -> Reason {
    let read: Vec<&&Site> = sites.iter().filter(|site| site.form.constructs()).collect();
    let files: BTreeSet<&str> = read.iter().map(|site| site.file.as_str()).collect();
    let files = files.into_iter().collect::<Vec<_>>().join("+");
    let (id, functions) = match measured {
        Measured::FileNotRun => (format!("{}:{files}", measured.name()), Vec::new()),
        Measured::FunctionNotEntered => {
            let functions: BTreeSet<(String, String)> = read
                .iter()
                .map(|site| (site.file.clone(), site.function.clone()))
                .collect();
            (
                format!("{}:{files}", measured.name()),
                functions.into_iter().collect(),
            )
        }
        Measured::NotConstructed => (format!("{}:{enum_path}", measured.name()), Vec::new()),
    };
    Reason {
        id,
        measured: measured.name().to_owned(),
        functions,
        kind: String::new(),
        missing: String::new(),
        sentence: String::new(),
    }
}

/// # Errors
///
/// `measure` returns `Err` when a variant's construction counts sum past
/// `u64::MAX`.
pub fn measure(
    source: &Source,
    coverage: &Coverage,
    family: &str,
    earlier: Option<&Register>,
    run: Run,
) -> Result<Register, String> {
    let mut reasons: Vec<Reason> = earlier
        .map(|register| register.reasons.clone())
        .unwrap_or_default();
    let kept: BTreeMap<(&str, &str), &str> = earlier
        .into_iter()
        .flat_map(|register| &register.rows)
        .filter_map(|row| Some((row.key(), row.reason.as_deref()?)))
        .collect();
    let mut added: BTreeMap<String, Reason> = BTreeMap::new();
    let mut refreshed: BTreeSet<String> = BTreeSet::new();
    let mut rows = Vec::new();
    for (enum_path, variant, sites) in variants(source, family) {
        let placement = mapping::place(&sites, coverage)?;
        let reason = placement
            .measured
            .map(|measured| -> Result<String, String> {
            let fresh = group(&enum_path, &sites, measured);
            let id = match kept.get(&(enum_path.as_str(), variant.as_str())) {
                Some(id)
                    if reasons
                        .iter()
                        .any(|reason| reason.id == *id && reason.measured == measured.name()) =>
                {
                    (*id).to_owned()
                }
                _ => fresh.id.clone(),
            };
            let target = match reasons.iter_mut().find(|known| known.id == id) {
                Some(known) if known.measured != measured.name() => {
                    return Err(format!(
                        "the reason row {id} has the class {}, and the row {enum_path}::{variant} measures {}",
                        known.measured,
                        measured.name()
                    ));
                }
                Some(known) => known,
                None => added.entry(id.clone()).or_insert_with(|| fresh.clone()),
            };
            if refreshed.insert(id.clone()) {
                target.functions.clear();
            }
            for function in fresh.functions {
                if !target.functions.contains(&function) {
                    target.functions.push(function);
                }
            }
            target.functions.sort();
            Ok(id)
        })
        .transpose()?;
        rows.push(Row {
            enum_path,
            variant,
            sites: triples(&sites),
            state: placement.state.name().to_owned(),
            count: (placement.state != State::Unplaced).then_some(placement.count),
            measured: placement
                .measured
                .map(|measured| measured.name().to_owned()),
            reason,
            cause: placement.cause.map(|cause| cause.name().to_owned()),
        });
    }
    reasons.extend(added.into_values());
    let totals = totals(&rows);
    Ok(Register {
        run,
        live: Live {
            unplaced: totals.unplaced,
        },
        totals,
        reasons,
        rows,
    })
}

fn totals(rows: &[Row]) -> Totals {
    let mut totals = Totals {
        rows: rows.len() as u64,
        ..Totals::default()
    };
    for row in rows {
        match row.state.as_str() {
            "reached" => totals.reached += 1,
            "unreached" => totals.unreached += 1,
            "unplaced" => totals.unplaced += 1,
            _ => {}
        }
        match row.measured.as_deref() {
            Some("file-not-run") => totals.file_not_run += 1,
            Some("function-not-entered") => totals.function_not_entered += 1,
            Some("not-constructed") => totals.not_constructed += 1,
            _ => {}
        }
    }
    totals
}

pub const UNMEASURED: &str = "unmeasured";

pub struct Synced {
    pub register: Register,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// `sync` preserves existing rows for `(enum_path, variant)` pairs returned
/// by `variants(source, family)`, adds an `unmeasured` row for each pair
/// that `variants(source, family)` returns and `register.rows` lacks, and
/// drops rows whose keys fall outside the set returned by
/// `variants(source, family)`. `sync` subtracts the number of dropped
/// `unplaced` rows from `live.unplaced`, saturating at zero; `run` and
/// `totals` stay as they are.
pub fn sync(source: &Source, family: &str, register: &Register) -> Synced {
    let mut earlier: BTreeMap<(String, String), Row> = register
        .rows
        .iter()
        .map(|row| ((row.enum_path.clone(), row.variant.clone()), row.clone()))
        .collect();
    let mut rows = Vec::new();
    let mut added = Vec::new();
    for (enum_path, variant, sites) in variants(source, family) {
        if let Some(row) = earlier.remove(&(enum_path.clone(), variant.clone())) {
            rows.push(row);
            continue;
        }
        added.push(format!("{enum_path}::{variant}"));
        rows.push(Row {
            enum_path,
            variant,
            sites: triples(&sites),
            state: UNMEASURED.to_owned(),
            count: None,
            measured: None,
            reason: None,
            cause: None,
        });
    }
    let dropped_unplaced = earlier
        .values()
        .filter(|row| row.state == "unplaced")
        .count() as u64;
    let removed = earlier
        .keys()
        .map(|(enum_path, variant)| format!("{enum_path}::{variant}"))
        .collect();
    let mut register = register.clone();
    register.rows = rows;
    register.live.unplaced = register.live.unplaced.saturating_sub(dropped_unplaced);
    Synced {
        register,
        added,
        removed,
    }
}

pub fn status(register: &Register) -> String {
    let unmeasured: Vec<&Row> = register
        .rows
        .iter()
        .filter(|row| row.state == UNMEASURED)
        .collect();
    let mut out = format!("unmeasured: {}\n", unmeasured.len());
    for row in unmeasured {
        out.push_str(&format!("{}::{}\n", row.enum_path, row.variant));
    }
    out
}

pub fn compare(register: &Register, measured: &Register) -> String {
    let states = |register: &Register| -> BTreeMap<(String, String), String> {
        register
            .rows
            .iter()
            .map(|row| {
                let shown = match row.count {
                    Some(count) => format!("{} {count}", row.state),
                    None => row.state.clone(),
                };
                ((row.enum_path.clone(), row.variant.clone()), shown)
            })
            .collect()
    };
    let (before, after) = (states(register), states(measured));
    let keys: BTreeSet<&(String, String)> = before.keys().chain(after.keys()).collect();
    let absent = "absent".to_owned();
    let mut out = String::new();
    for key in keys {
        let (old, new) = (
            before.get(key).unwrap_or(&absent),
            after.get(key).unwrap_or(&absent),
        );
        if old != new {
            out.push_str(&format!("{}::{}: {old} -> {new}\n", key.0, key.1));
        }
    }
    out
}
