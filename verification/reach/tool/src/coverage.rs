//! The mapper reads per-file coverage from `llvm-cov export -format=text`:
//! each file's segments, whether a line of it ran, and the spans of its
//! function instantiations with their entry counts.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::source::At;

#[derive(Deserialize)]
struct Export {
    data: Vec<Data>,
}

#[derive(Deserialize)]
struct Data {
    files: Vec<File>,
    functions: Vec<Function>,
}

#[derive(Deserialize)]
struct File {
    filename: String,
    segments: Vec<Segment>,
    summary: Summary,
}

/// LLVM writes a segment as the array `[line, column, count, has_count,
/// is_region_entry, is_gap_region]`. A segment without a count leaves its
/// span uncounted; a gap segment counts like any other.
#[derive(Deserialize)]
struct Segment(usize, usize, u64, bool, bool, bool);

#[derive(Deserialize)]
struct Summary {
    lines: Lines,
}

#[derive(Deserialize)]
struct Lines {
    covered: u64,
}

#[derive(Deserialize)]
struct Function {
    count: u64,
    regions: Vec<Vec<u64>>,
    filenames: Vec<String>,
}

#[derive(Debug, Default)]
struct FileCoverage {
    segments: Vec<(At, Option<u64>)>,
    ran: bool,
    functions: Vec<(At, At, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    Uncounted,
    Count(u64),
}

#[derive(Debug, Default)]
pub struct Coverage {
    files: BTreeMap<String, FileCoverage>,
}

/// The suffix following `ROOT` in an export file name gives the
/// source-relative path.
const ROOT: &str = "crates/kestrike/src/";

impl Coverage {
    /// # Errors
    ///
    /// `read` returns an error prefixed with `export: ` when `serde_json`
    /// cannot deserialize `text` as an export.
    pub fn read(text: &str) -> Result<Self, String> {
        let export: Export =
            serde_json::from_str(text).map_err(|error| format!("export: {error}"))?;
        let mut files: BTreeMap<String, FileCoverage> = BTreeMap::new();
        for data in export.data {
            for file in data.files {
                let Some(rel) = relative(&file.filename) else {
                    continue;
                };
                let entry = files.entry(rel).or_default();
                entry.ran |= file.summary.lines.covered > 0;
                entry.segments.extend(file.segments.iter().map(
                    |&Segment(line, column, count, has_count, _entry, _gap)| {
                        ((line, column), has_count.then_some(count))
                    },
                ));
                entry.segments.sort_by_key(|segment| segment.0);
            }
            for function in data.functions {
                let Some(rel) = function.filenames.first().and_then(|name| relative(name)) else {
                    continue;
                };
                let code = function
                    .regions
                    .iter()
                    .filter_map(|region| code_span(region));
                let start = code.clone().map(|(start, _)| start).min();
                let end = code.map(|(_, end)| end).max();
                if let (Some(start), Some(end)) = (start, end) {
                    files
                        .entry(rel)
                        .or_default()
                        .functions
                        .push((start, end, function.count));
                }
            }
        }
        if files.is_empty() {
            return Err(format!("export: no file under {ROOT}"));
        }
        Ok(Self { files })
    }

    /// The count of the last segment that starts at or before `at`.
    pub fn region(&self, file: &str, at: At) -> Region {
        let Some(coverage) = self.files.get(file) else {
            return Region::Uncounted;
        };
        let after = coverage.segments.partition_point(|segment| segment.0 <= at);
        match after.checked_sub(1).map(|index| coverage.segments[index].1) {
            Some(Some(count)) => Region::Count(count),
            _ => Region::Uncounted,
        }
    }

    pub fn file_ran(&self, file: &str) -> bool {
        self.files.get(file).is_some_and(|coverage| coverage.ran)
    }

    pub fn entered(&self, file: &str, at: At) -> bool {
        self.files.get(file).is_some_and(|coverage| {
            coverage
                .functions
                .iter()
                .any(|(start, end, count)| *start <= at && at <= *end && *count > 0)
        })
    }
}

/// LLVM writes a function region as the array `[line_start, column_start,
/// line_end, column_end, execution_count, file_id, expanded_file_id, kind]`.
/// File id 0 indexes the first of the function's `filenames`, and kind 0 is a
/// code region. `code_span` returns the bounds of a code region in file 0 and
/// `None` for every other region and for an array shorter than eight.
fn code_span(region: &[u64]) -> Option<(At, At)> {
    match *region {
        [
            line_start,
            column_start,
            line_end,
            column_end,
            _count,
            0,
            _expanded,
            0,
            ..,
        ] => Some((
            (line_start as usize, column_start as usize),
            (line_end as usize, column_end as usize),
        )),
        _ => None,
    }
}

fn relative(name: &str) -> Option<String> {
    name.split_once(ROOT).map(|(_, rel)| rel.to_owned())
}
