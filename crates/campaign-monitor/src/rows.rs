//! Parallel reading of a snapshot's job and finding rows. A structural index
//! of the text locates the top-level `jobs` and `findings` arrays and the
//! commas between their rows. The snapshot then parses with those arrays
//! emptied, and the job rows and the finding rows each parse on up to
//! [`THREADS`] threads, the finding rows on a thread of their own beside
//! the job rows.
//!
//! The index is built in two parallel passes over chunks of the text. The
//! first finds, for each chunk, how its quotes flip string state and how
//! its brackets change nesting depth, for both possible string states at
//! the chunk's start; a chunk starts after a byte other than a backslash,
//! so no escape crosses into it. Folding those summaries in order gives
//! each chunk's true starting state, and the second pass records the
//! structural bytes at nesting levels zero through two.
//!
//! The index only locates bytes. serde_json parses every byte outside the
//! two row arrays in the emptied snapshot and every row on its own; the
//! remaining bytes are checked to be each array's `[` and `]` and the
//! commas and whitespace between its rows. So a snapshot [`read`] returns
//! equals the derived reader's, and [`read`] returns `None` for every text
//! the derived reader refuses.

use serde::de::DeserializeOwned;

use crate::parallel::{self, THREADS};
use crate::snapshot::Snapshot;

/// The rows per parse thread that [`parallel::runs`] aims for, so the
/// rows of one small array parse on one thread.
const ROWS_PER_THREAD: usize = 128;

/// The bytes per index thread that [`chunks`] aims for.
const SCAN_BYTES: usize = 256 << 10;

/// `marks` returns `None` when adding a mark would exceed this count.
const MARKS_PER_CHUNK: usize = 1 << 18;

/// `text` as a snapshot with its rows parsed in parallel; `None` when the
/// derived reader refuses the text, or when the index finds a top-level
/// shape other than an object of members.
pub(crate) fn read(text: &str) -> Option<Snapshot> {
    let bytes = text.as_bytes();
    let arrays = row_arrays(bytes, index(bytes)?.into_iter().flatten())?;
    let removed: usize = arrays.iter().map(|array| array.end - array.start).sum();
    let mut emptied = String::with_capacity(text.len() - removed + 2 * arrays.len());
    let mut at = 0;
    for array in &arrays {
        emptied.push_str(&text[at..array.start]);
        emptied.push_str("[]");
        at = array.end;
    }
    emptied.push_str(&text[at..]);
    let mut snapshot: Snapshot = serde_json::from_str(&emptied).ok()?;
    // A field named twice fails the parse above, so each name holds at
    // most one array here.
    let (mut jobs, mut findings) = (None, None);
    for array in arrays {
        match array.field {
            Field::Jobs => jobs = Some(array.rows),
            Field::Findings => findings = Some(array.rows),
        }
    }
    let parse_findings = findings.as_ref().map(|rows| move || parse_rows(text, rows));
    let (jobs, findings) = std::thread::scope(|scope| {
        let findings = parse_findings
            .as_ref()
            .map(|task| parallel::start(scope, task));
        let jobs = jobs.map(|rows| parse_rows(text, &rows));
        (jobs, findings.map(parallel::Worker::finish))
    });
    if let Some(jobs) = jobs {
        snapshot.jobs = jobs?;
    }
    if let Some(findings) = findings {
        snapshot.findings = findings?;
    }
    Some(snapshot)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Jobs,
    Findings,
}

/// One top-level row array: the byte range from its `[` through its `]`,
/// and the byte range of each row, whitespace trimmed.
#[derive(Debug)]
struct RowArray {
    field: Field,
    start: usize,
    end: usize,
    rows: Vec<(usize, usize)>,
}

/// A structural byte outside strings: an opening or closing bracket at
/// nesting levels zero through two, or a comma, colon or opening quote at
/// level one or two. `depth` is the level of the container the byte belongs to: the
/// root object is level one, so its own brackets are at level zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mark {
    at: usize,
    depth: usize,
    byte: u8,
}

/// How one chunk changes string state and nesting depth. `flips` is true
/// when the chunk holds an odd number of unescaped quotes. `outside` and
/// `inside` are the depth changes of the chunk's brackets when the chunk
/// starts outside or inside a string.
#[derive(Debug, Clone, Copy)]
struct Summary {
    flips: bool,
    outside: isize,
    inside: isize,
}

/// `index` returns the structural marks of `bytes` in text order, one
/// vector per chunk, or `None` when a closing bracket leaves the root.
fn index(bytes: &[u8]) -> Option<Vec<Vec<Mark>>> {
    let chunks = chunks(bytes);
    let summaries = parallel::each(&chunks, |&(start, end)| summarize(&bytes[start..end]));
    let mut starts = Vec::with_capacity(chunks.len());
    let (mut inside, mut depth) = (false, 0isize);
    for summary in summaries {
        starts.push((inside, usize::try_from(depth).ok()?));
        depth += if inside {
            summary.inside
        } else {
            summary.outside
        };
        inside ^= summary.flips;
    }
    let work: Vec<_> = chunks.into_iter().zip(starts).collect();
    let marks = parallel::each(&work, |&((start, end), (inside, depth))| {
        marks(bytes, start, end, inside, depth)
    });
    marks.into_iter().collect()
}

/// Splits `bytes` into `bytes.len() / SCAN_BYTES` chunks, clamped to
/// `1..=THREADS`, each starting after a byte other than a backslash.
fn chunks(bytes: &[u8]) -> Vec<(usize, usize)> {
    let count = (bytes.len() / SCAN_BYTES).clamp(1, THREADS);
    let mut chunks = Vec::with_capacity(count);
    let mut start = 0;
    for part in 1..count {
        let mut end = (bytes.len() * part / count).max(start);
        while end < bytes.len() && end > 0 && bytes[end - 1] == b'\\' {
            end += 1;
        }
        chunks.push((start, end));
        start = end;
    }
    chunks.push((start, bytes.len()));
    chunks
}

/// The byte classes the index loops branch on; every other byte is
/// [`PLAIN`].
const PLAIN: u8 = 0;
const BACKSLASH: u8 = 1;
const QUOTE: u8 = 2;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const SEPARATOR: u8 = 5;

const CLASSES: [u8; 256] = {
    let mut classes = [PLAIN; 256];
    classes[b'\\' as usize] = BACKSLASH;
    classes[b'"' as usize] = QUOTE;
    classes[b'{' as usize] = OPEN;
    classes[b'[' as usize] = OPEN;
    classes[b'}' as usize] = CLOSE;
    classes[b']' as usize] = CLOSE;
    classes[b',' as usize] = SEPARATOR;
    classes[b':' as usize] = SEPARATOR;
    classes
};

/// The [`Summary`] of `chunk`. A backslash escapes the byte after it
/// wherever it stands, which matches JSON, where a backslash stands only
/// inside a string.
fn summarize(chunk: &[u8]) -> Summary {
    let mut inside = false;
    let (mut outside_depth, mut inside_depth) = (0isize, 0isize);
    let mut escaped = false;
    for &byte in chunk {
        let class = CLASSES[usize::from(byte)];
        if class == PLAIN {
            escaped = false;
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        let change = match class {
            BACKSLASH => {
                escaped = true;
                continue;
            }
            QUOTE => {
                inside = !inside;
                continue;
            }
            OPEN => 1,
            CLOSE => -1,
            _ => continue,
        };
        if inside {
            inside_depth += change;
        } else {
            outside_depth += change;
        }
    }
    Summary {
        flips: inside,
        outside: outside_depth,
        inside: inside_depth,
    }
}

/// The marks of `bytes[start..end]`, which starts in the given string
/// state at nesting `depth`; `None` when a closing bracket leaves the root
/// or the chunk holds more than [`MARKS_PER_CHUNK`] marks.
fn marks(bytes: &[u8], start: usize, end: usize, inside: bool, depth: usize) -> Option<Vec<Mark>> {
    let mut marks = Vec::new();
    let mut push = |mark: Mark| {
        if marks.len() == MARKS_PER_CHUNK {
            return None;
        }
        marks.push(mark);
        Some(())
    };
    let (mut inside, mut depth) = (inside, depth);
    let mut escaped = false;
    for (at, &byte) in bytes[start..end].iter().enumerate() {
        let class = CLASSES[usize::from(byte)];
        if class == PLAIN {
            escaped = false;
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        let at = start + at;
        match class {
            BACKSLASH => escaped = true,
            QUOTE => {
                if !inside && (1..=2).contains(&depth) {
                    push(Mark { at, depth, byte })?;
                }
                inside = !inside;
            }
            _ if inside => {}
            OPEN => {
                if depth <= 2 {
                    push(Mark { at, depth, byte })?;
                }
                depth += 1;
            }
            CLOSE => {
                depth = depth.checked_sub(1)?;
                if depth <= 2 {
                    push(Mark { at, depth, byte })?;
                }
            }
            _ => {
                if (1..=2).contains(&depth) {
                    push(Mark { at, depth, byte })?;
                }
            }
        }
    }
    Some(marks)
}

/// The arrays held by the top-level members named `jobs` and `findings`,
/// in text order, read from `marks`; `None` when the marks do not form an
/// object of members.
fn row_arrays(bytes: &[u8], marks: impl Iterator<Item = Mark>) -> Option<Vec<RowArray>> {
    let mut arrays = Vec::new();
    let mut marks = marks.peekable();
    let root = marks.next()?;
    if (root.byte, root.depth, root.at) != (b'{', 0, skip_space(bytes, 0)) {
        return None;
    }
    if marks.peek().is_some_and(|mark| mark.depth == 0) {
        return (marks.next()?.byte == b'}').then_some(arrays);
    }
    loop {
        let key = marks.next()?;
        if (key.byte, key.depth) != (b'"', 1) {
            return None;
        }
        let field = match &bytes[key.at..skip_string(bytes, key.at)?] {
            b"\"jobs\"" => Some(Field::Jobs),
            b"\"findings\"" => Some(Field::Findings),
            _ => None,
        };
        let colon = marks.next()?;
        if (colon.byte, colon.depth) != (b':', 1) {
            return None;
        }
        let value = skip_space(bytes, colon.at + 1);
        let mut rows = field.is_some().then(Vec::new);
        let mut row = value + 1;
        let mut next = marks.next()?;
        if next.at == value {
            match next.byte {
                b'"' => next = marks.next()?,
                b'{' | b'[' => {
                    loop {
                        next = marks.next()?;
                        match (next.depth, next.byte) {
                            (1, _) => break,
                            (2, b',') => {
                                if let Some(rows) = &mut rows {
                                    rows.push(trim(bytes, row, next.at)?);
                                }
                                row = next.at + 1;
                            }
                            _ => {}
                        }
                    }
                    if !matches!(next.byte, b'}' | b']') {
                        return None;
                    }
                    if let (Some(field), Some(mut rows)) = (field, rows)
                        && bytes[value] == b'['
                    {
                        if next.byte != b']' {
                            return None;
                        }
                        match trim(bytes, row, next.at) {
                            Some(last) => rows.push(last),
                            None if rows.is_empty() => {}
                            None => return None,
                        }
                        arrays.push(RowArray {
                            field,
                            start: value,
                            end: next.at + 1,
                            rows,
                        });
                    }
                    next = marks.next()?;
                }
                _ => {}
            }
        }
        match (next.depth, next.byte) {
            (1, b',') => {}
            (0, b'}') => return Some(arrays),
            _ => return None,
        }
    }
}

/// The range `start..end` without its leading and trailing JSON
/// whitespace; `None` when nothing else remains.
fn trim(bytes: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
    let held = &bytes[start..end];
    let first = held.iter().position(|byte| !space(byte))?;
    let last = held.iter().rposition(|byte| !space(byte))?;
    Some((start + first, start + last + 1))
}

fn skip_space(bytes: &[u8], mut at: usize) -> usize {
    while matches!(bytes.get(at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        at += 1;
    }
    at
}

/// The end of the string whose opening quote is at `at`, past its closing
/// quote. A backslash escapes the byte after it.
fn skip_string(bytes: &[u8], at: usize) -> Option<usize> {
    let mut next = at + 1;
    loop {
        match bytes.get(next)? {
            b'"' => return Some(next + 1),
            b'\\' => next += 2,
            _ => next += 1,
        }
    }
}

/// Parses the rows at `spans` of `text`, in order, in the runs
/// [`parallel::runs`] forms for [`ROWS_PER_THREAD`]; `None` when any row
/// fails to parse.
fn parse_rows<T: DeserializeOwned + Send>(text: &str, spans: &[(usize, usize)]) -> Option<Vec<T>> {
    let mut rows = Vec::with_capacity(spans.len());
    for run in parallel::runs(spans, ROWS_PER_THREAD, |run| parse_run(text, run)) {
        rows.extend(run?);
    }
    Some(rows)
}

/// Parses each row at the nesting depth it holds in a snapshot, inside the
/// snapshot object and its row array, so the parser's recursion bound
/// applies to it as it does in the whole text.
fn parse_run<T: DeserializeOwned>(text: &str, spans: &[(usize, usize)]) -> Option<Vec<T>> {
    let mut nested = String::new();
    spans
        .iter()
        .map(|&(start, end)| {
            nested.clear();
            nested.push_str("[[");
            nested.push_str(&text[start..end]);
            nested.push_str("]]");
            let [[parsed]] = serde_json::from_str::<[[T; 1]; 1]>(&nested).ok()?;
            Some(parsed)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> serde_json::Value {
        serde_json::json!({
            "format": 1, "observed_ms": 5, "state": "/s", "config": null, "probes": 0,
            "held_probes": [],
            "jobs": [], "findings": [], "failure_groups": [],
            "space": {"free_bytes": 1, "free_inodes": 1},
        })
    }

    fn arrays_of(text: &str) -> Option<Vec<RowArray>> {
        row_arrays(
            text.as_bytes(),
            index(text.as_bytes())?.into_iter().flatten(),
        )
    }

    #[test]
    fn the_index_finds_each_row_of_the_top_level_row_arrays() {
        let text = r#" {"a": {"jobs": [1]}, "jobs" : [ {"x": "]\"},{"} , [2] ],
            "findings": [ ], "f": "jobs", "jobs": 3, "g": ["x", {"y": [1, 2]}] } "#;
        let arrays = arrays_of(text).unwrap();
        assert_eq!(arrays.len(), 2);
        let rows: Vec<&str> = arrays[0]
            .rows
            .iter()
            .map(|&(start, end)| &text[start..end])
            .collect();
        assert_eq!(rows, [r#"{"x": "]\"},{"}"#, "[2]"]);
        let held = &text[arrays[0].start..arrays[0].end];
        assert!(held.starts_with("[ {") && held.ends_with("[2] ]"), "{held}");
        assert_eq!(arrays[1].field, Field::Findings);
        assert!(arrays[1].rows.is_empty());
        let empty = arrays_of("{}").unwrap();
        assert!(empty.is_empty());
        for broken in [
            r#"{"jobs": [1,,2]}"#,
            r#"{"jobs": [1,]}"#,
            r#"{"jobs": [1,"#,
            r#"{"jobs" [1]}"#,
            r#"{"a": 1 "b": 2}"#,
            "[]",
            "{}}",
        ] {
            assert!(arrays_of(broken).is_none(), "{broken}");
        }
    }

    #[test]
    fn every_chunking_of_a_text_indexes_it_alike() {
        let row = r#"{"id": "a\\\"b{[", "x": [{"y": "\\"}, 2], "z": "}]\\\\"}"#;
        let rows = vec![row; 40].join(" ,\n");
        let text = format!(r#"{{"jobs": [{rows}], "findings": [{rows}], "s": "\\"}}"#);
        let bytes = text.as_bytes();
        let whole = marks(bytes, 0, bytes.len(), false, 0).unwrap();
        for count in 2..9 {
            for shift in 0..7 {
                let mut cuts: Vec<usize> = (1..count)
                    .map(|part| bytes.len() * part / count + shift)
                    .map(|cut| {
                        let mut cut = cut.min(bytes.len());
                        while cut < bytes.len() && bytes[cut - 1] == b'\\' {
                            cut += 1;
                        }
                        cut
                    })
                    .collect();
                cuts.dedup();
                let mut starts = vec![0];
                starts.extend(&cuts);
                let mut ends = cuts.clone();
                ends.push(bytes.len());
                let (mut inside, mut depth) = (false, 0isize);
                let mut found = Vec::new();
                for (start, end) in starts.into_iter().zip(ends) {
                    let summary = summarize(&bytes[start..end]);
                    let depth_at = usize::try_from(depth).unwrap();
                    found.extend(marks(bytes, start, end, inside, depth_at).unwrap());
                    depth += if inside {
                        summary.inside
                    } else {
                        summary.outside
                    };
                    inside ^= summary.flips;
                }
                assert_eq!(found, whole, "{count} {shift}");
            }
        }
        let arrays = row_arrays(bytes, whole.iter().copied()).unwrap();
        assert!(arrays.iter().all(|array| array.rows.len() == 40));
        assert!(
            arrays[0]
                .rows
                .iter()
                .all(|&(start, end)| &text[start..end] == row)
        );
    }

    #[test]
    fn a_chunk_past_the_mark_bound_leaves_the_text_to_the_derived_reader() {
        let dense = |separators: usize| format!("{{\"jobs\":[{}", ",".repeat(separators));
        let under = dense(1000);
        assert!(index(under.as_bytes()).is_some());
        assert!(Snapshot::parse(&under).is_err());
        let over = dense(THREADS * (MARKS_PER_CHUNK + 16));
        assert!(chunks(over.as_bytes()).len() == THREADS);
        assert!(index(over.as_bytes()).is_none());
        let error = Snapshot::parse(&over).unwrap_err();
        assert!(error.contains("not a format-1 snapshot"), "{error}");
    }

    /// The reader and the derived reader agree on `text`: both refuse it,
    /// or both accept it with equal snapshots.
    fn agree(text: &str) {
        let derived = serde_json::from_str::<Snapshot>(text).ok();
        let parallel = read(text);
        assert_eq!(
            parallel.map(|snapshot| format!("{snapshot:?}")),
            derived.map(|snapshot| format!("{snapshot:?}")),
            "{text}"
        );
    }

    #[test]
    fn every_one_byte_change_of_a_snapshot_reads_as_the_derived_reader_reads_it() {
        let mut shown = complete();
        shown["jobs"] = serde_json::json!([
            {"id": "a", "state": "settled", "result": {"attempt": 1, "class": "pass"},
             "attempts": [{"number": 1, "finished": {"class": "pass", "kernel": {"memory": {"oom": 0}}}}]},
            {"id": "b\"]},{", "state": "queued", "attempts": []},
        ]);
        shown["findings"] = serde_json::json!([{"id": "f", "verified": {"x": [1, {"y": "\\"}]}}]);
        let text = shown.to_string();
        agree(&text);
        for at in 0..text.len() {
            let mut cut = text.clone();
            cut.remove(at);
            agree(&cut);
            for byte in ['{', '}', '[', ']', ',', ':', '"', '\\', ' ', '1'] {
                let mut changed = text.clone();
                changed.replace_range(at..=at, byte.encode_utf8(&mut [0; 4]));
                agree(&changed);
            }
        }
    }

    #[test]
    fn parallel_rows_read_exactly_what_the_derived_reader_reads() {
        let row = |n: usize| {
            serde_json::json!({"id": format!("j{n}"), "state": "settled", "run": n,
                               "result": {"attempt": 1, "class": "pass"},
                               "attempts": [{"number": 1, "finished": {"class": "pass"}}]})
        };
        let mut many = complete();
        many["jobs"] = (0..3 * ROWS_PER_THREAD).map(row).collect();
        many["findings"] = (0..2 * ROWS_PER_THREAD)
            .map(|n| serde_json::json!({"id": format!("f{n}"), "verified": {}}))
            .collect();
        let text = many.to_string();
        let parallel = read(&text).unwrap();
        let derived: Snapshot = serde_json::from_str(&text).unwrap();
        assert_eq!(format!("{parallel:?}"), format!("{derived:?}"));
        let pretty = serde_json::to_string_pretty(&many).unwrap();
        let parallel = read(&pretty).unwrap();
        assert_eq!(format!("{parallel:?}"), format!("{derived:?}"));

        let deep = |depth: usize| {
            let mut nested = complete();
            let value = "[".repeat(depth) + &"]".repeat(depth);
            nested["jobs"] = serde_json::json!([{"id": "j", "deep": "x"}]);
            nested.to_string().replace("\"x\"", &value)
        };
        for depth in 120..130 {
            let text = deep(depth);
            let derived = serde_json::from_str::<Snapshot>(&text).is_ok();
            assert_eq!(read(&text).is_some(), derived, "depth {depth}");
        }
        let mut bad = many.clone();
        bad["jobs"][2 * ROWS_PER_THREAD]["run"] = serde_json::json!("x");
        bad["findings"][0]["id"] = serde_json::json!(7);
        let error = Snapshot::parse(&bad.to_string()).unwrap_err();
        assert!(error.contains("expected a string"), "{error}");
    }
}
