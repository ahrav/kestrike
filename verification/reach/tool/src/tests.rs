//! `parse` resolves sites through renames, `Self` and globs, and skips
//! patterns and test code. A site takes the count of its own segment, or of
//! the `?` that ends its chain when it is an eager argument or a function
//! value. `measure` places every row and writes a register that
//! `Register::read` reads back, and `sync` adds an `unmeasured` row for
//! each new variant.

use std::collections::BTreeMap;

use crate::coverage::Coverage;
use crate::mapping::{Cause, Measured, State, place};
use crate::modes::{measure, status, sync};
use crate::register::{Register, Run};
use crate::source::{Form, Source, parse};

const DISK: &str = "storage/disk.rs";
const ENUM: &str = "pub enum DiskError { Full, Gone(u8), Torn { at: u8 } }\n";

fn files(body: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "mod.rs".to_owned(),
            "pub mod storage;\n#[cfg(test)]\nmod tests;\n".to_owned(),
        ),
        ("storage/mod.rs".to_owned(), "pub mod disk;\n".to_owned()),
        (DISK.to_owned(), format!("{ENUM}{body}")),
    ])
}

fn parsed(files: &BTreeMap<String, String>) -> Source {
    parse(&|rel: &str| Ok(files.get(rel).cloned())).expect("the fixture parses")
}

fn refused(files: &BTreeMap<String, String>) -> String {
    parse(&|rel: &str| Ok(files.get(rel).cloned())).expect_err("the fixture is refused")
}

/// `at` returns the 1-based line and byte column of the match at zero-based
/// index `nth`.
fn at(text: &str, needle: &str, nth: usize) -> (usize, usize) {
    let offset = text
        .match_indices(needle)
        .nth(nth)
        .unwrap_or_else(|| panic!("{needle} occurs {} times", nth + 1))
        .0;
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let column = offset - before.rfind('\n').map_or(0, |newline| newline + 1) + 1;
    (line, column)
}

fn export(segments: &[((usize, usize), Option<u64>)], entered: u64, covered: u64) -> Coverage {
    Coverage::read(&export_text(segments, entered, covered)).expect("the fixture export parses")
}

fn export_text(segments: &[((usize, usize), Option<u64>)], entered: u64, covered: u64) -> String {
    let name = format!("/w/crates/kestrike/src/{DISK}");
    let segments: Vec<String> = segments.iter().map(segment).collect();
    let region = code_region((1, 1), (999, 1), entered);
    format!(
        r#"{{"data":[{{"files":[{{"filename":"{name}","segments":[{}],"summary":{{"lines":{{"covered":{covered}}}}}}}],
        "functions":[{{"count":{entered},"regions":[{region}],"filenames":["{name}"]}}]}}]}}"#,
        segments.join(",")
    )
}

fn segment(&((line, column), count): &((usize, usize), Option<u64>)) -> String {
    format!(
        "[{line},{column},{count},{has_count},{is_region_entry},{is_gap_region}]",
        count = count.unwrap_or(0),
        has_count = count.is_some(),
        is_region_entry = true,
        is_gap_region = false,
    )
}

fn code_region(
    (line_start, column_start): (usize, usize),
    (line_end, column_end): (usize, usize),
    count: u64,
) -> String {
    format!(
        "[{line_start},{column_start},{line_end},{column_end},{count},{file_id},{expanded_file_id},{kind}]",
        file_id = 0,
        expanded_file_id = 0,
        kind = 0,
    )
}

fn placed(source: &Source, variant: &str, coverage: &Coverage) -> crate::mapping::Placement {
    let sites: Vec<_> = source.sites_of(0, variant).collect();
    place(&sites, coverage).expect("the counts sum within u64")
}

#[test]
fn a_site_takes_the_count_of_its_own_segment() {
    let body = "fn f() -> Result<(), DiskError> { Err(DiskError::Full) }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let coverage = export(&[(at(&text, "DiskError::Full", 0), Some(3))], 1, 1);
    let placement = placed(&source, "Full", &coverage);
    assert_eq!((placement.state, placement.count), (State::Reached, 3));
}

#[test]
fn an_eager_argument_takes_the_count_of_the_question_mark_that_ends_its_chain() {
    let body = "fn f(x: Option<u8>) -> Result<u8, DiskError> { let v = x.ok_or(DiskError::Full)?; Ok(v) }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let site = source.sites_of(0, "Full").next().expect("one site");
    assert_eq!(site.form, Form::Eager);
    for (question, state) in [(0, State::Unreached), (2, State::Reached)] {
        let coverage = export(
            &[
                (at(&text, "DiskError::Full", 0), Some(5)),
                (at(&text, "?;", 0), Some(question)),
            ],
            1,
            1,
        );
        let placement = placed(&source, "Full", &coverage);
        assert_eq!((placement.state, placement.count), (state, question));
    }
}

#[test]
fn a_function_value_takes_the_count_of_the_question_mark_that_ends_its_chain() {
    let body = "fn f(x: Result<u8, u8>) -> Result<u8, DiskError> { let v = x.map_err(DiskError::Gone)?; Ok(v) }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    assert_eq!(
        source.sites_of(0, "Gone").next().map(|site| site.form),
        Some(Form::Value)
    );
    let coverage = export(
        &[
            (at(&text, "DiskError::Gone", 0), None),
            (at(&text, "?;", 0), Some(4)),
        ],
        1,
        1,
    );
    let placement = placed(&source, "Gone", &coverage);
    assert_eq!((placement.state, placement.count), (State::Reached, 4));
}

#[test]
fn a_closure_that_never_ran_takes_a_zero_count_from_its_outer_question_mark() {
    let body = "fn f(x: Result<u8, u8>) -> Result<u8, DiskError> { let v = x.map_err(|_| DiskError::Full)?; Ok(v) }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let segments = |question| {
        export(
            &[
                (at(&text, "DiskError::Full", 0), None),
                (at(&text, "?;", 0), Some(question)),
            ],
            1,
            1,
        )
    };
    let unreached = placed(&source, "Full", &segments(0));
    assert_eq!(
        (unreached.state, unreached.measured),
        (State::Unreached, Some(Measured::NotConstructed))
    );
    let unplaced = placed(&source, "Full", &segments(4));
    assert_eq!(
        (unplaced.state, unplaced.cause),
        (State::Unplaced, Some(Cause::NoRegion))
    );
}

#[test]
fn a_comparison_and_a_table_are_no_reach() {
    let body = "fn f(e: &DiskError) -> bool { *e == DiskError::Full }\nconst ALL: [DiskError; 1] = [DiskError::Full];\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let forms: Vec<Form> = source.sites_of(0, "Full").map(|site| site.form).collect();
    assert_eq!(forms, [Form::Compare, Form::Table]);
    let coverage = export(
        &[
            (at(&text, "DiskError::Full", 0), Some(9)),
            (at(&text, "DiskError::Full", 1), Some(9)),
        ],
        9,
        2,
    );
    let placement = placed(&source, "Full", &coverage);
    assert_eq!(
        (placement.state, placement.cause),
        (State::Unplaced, Some(Cause::NoSite))
    );
}

#[test]
fn an_executed_eager_argument_with_no_question_mark_is_unplaced() {
    let body = "fn f(x: Option<u8>) -> Result<u8, DiskError> { x.ok_or(DiskError::Full) }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let coverage = export(&[(at(&text, "DiskError::Full", 0), Some(7))], 7, 1);
    let placement = placed(&source, "Full", &coverage);
    assert_eq!(
        (placement.state, placement.cause),
        (State::Unplaced, Some(Cause::Unplaceable))
    );
}

#[test]
fn an_unreached_variant_records_how_far_the_run_came() {
    let body = "fn f() -> Result<(), DiskError> { Err(DiskError::Full) }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let site = at(&text, "DiskError::Full", 0);
    assert!(Coverage::read(r#"{"data":[{"files":[],"functions":[]}]}"#).is_err());
    for (coverage, measured) in [
        (export(&[(site, Some(0))], 0, 0), Measured::FileNotRun),
        (
            export(&[(site, Some(0))], 0, 3),
            Measured::FunctionNotEntered,
        ),
        (export(&[(site, Some(0))], 2, 3), Measured::NotConstructed),
    ] {
        let placement = placed(&source, "Full", &coverage);
        assert_eq!(
            (placement.state, placement.measured),
            (State::Unreached, Some(measured))
        );
    }
}

#[test]
fn sites_resolve_through_renames_self_and_globs_and_skip_patterns_and_test_code() {
    let body = "\
fn renamed() -> DiskError { use DiskError::Gone as G; G(1) }
impl DiskError { fn torn() -> Self { Self::Torn { at: 1 } } }
mod inner { use super::DiskError::*; fn bare() -> super::DiskError { Full } }
fn patterns(e: DiskError) -> bool { if let DiskError::Full = e { return true; } matches!(e, DiskError::Gone(_)) }
#[cfg(test)]
fn gated() -> DiskError { DiskError::Full }
#[cfg(any(kani, loom))]
fn proof() -> DiskError { DiskError::Full }
fn tested() { #[cfg(test)] { let _ = DiskError::Full; } let _ = S { #[cfg(test)] e: DiskError::Full }; }
";
    let source = parsed(&files(body));
    let sites: Vec<(String, String, Form)> = source
        .sites
        .iter()
        .map(|site| (site.variant.clone(), site.function.clone(), site.form))
        .collect();
    assert_eq!(
        sites,
        [
            ("Gone".to_owned(), "renamed".to_owned(), Form::Call),
            (
                "Torn".to_owned(),
                "DiskError::torn".to_owned(),
                Form::Struct
            ),
            ("Full".to_owned(), "bare".to_owned(), Form::Path),
        ]
    );
}

#[test]
fn the_listed_enums_are_the_family_enums_with_a_listed_ending() {
    let mut files = files(
        "pub enum DiskState { Idle }\npub enum ErrorKind { A }\npub enum ReasonCode { A }\nmod inner { pub enum InnerRefusal { A } }\nimpl DiskError { #[cfg(test)] fn probe() { enum ProbeError { A } } }\ntrait Probe { #[cfg(test)] fn probe() { enum ProbeFailure { A } } }\nimpl DiskError { fn made() { enum MadeError { A } } }\ntrait Shape { fn made() { enum ShapeFailure { A } } }\n",
    );
    files.insert(
        "mod.rs".to_owned(),
        "pub mod storage;\nmod sim;\n".to_owned(),
    );
    files.insert(
        "sim.rs".to_owned(),
        "pub enum SimError { Lost }\n".to_owned(),
    );
    let source = parsed(&files);
    let listed: Vec<&str> = source
        .listed("storage")
        .into_iter()
        .map(|index| source.enums[index].path.as_str())
        .collect();
    assert_eq!(
        listed,
        [
            "storage::disk::DiskError",
            "storage::disk::MadeError",
            "storage::disk::ShapeFailure",
            "storage::disk::inner::InnerRefusal"
        ]
    );
    assert!(source.listed("net").is_empty());
}

/// A call argument, a parenthesized expression, an array element, an
/// array length and a negated group each hold a block whose enums are
/// declared. A statement or a match arm under a gating attribute declares
/// none, a parameter's attribute leaves the function's body in the build,
/// and the arms after a gated arm and the fields after a gated field stay
/// in the build.
#[test]
fn an_enum_declared_inside_an_expression_group_is_listed() {
    let source = parsed(&files(
        "fn call() { consume({ enum CallError { Lost } }); }\nfn paren() { let _ = ({ enum ParenError { Lost } }); }\nfn array() { let _ = [{ enum ArrayError { Lost } 0u8 }]; }\nfn length(_: [u8; { enum LengthError { Lost } 1 }]) {}\nfn body(#[cfg(test)] _probe: u8) { enum BodyError { Lost } }\nfn not() { if !({ enum NotError { Lost } true }) {} }\nfn late(x: u8) -> u8 { match x { #[cfg(test)] 0 => 1, _ => consume({ enum LateError { Lost } }) } }\nfn last(x: u8) -> u8 { match x { #[cfg(test)] 0 => pick::<u8, u8>({ enum EarlyError { Lost } }), _ => consume({ enum LastError { Lost } }) } }\nfn field() -> S { S { #[cfg(test)] a: consume({ enum GoneError { Lost } }), b: consume({ enum FieldError { Lost } }) } }\nfn short(a: u8) -> S { S { #[cfg(test)] a, b: consume({ enum ShortError { Lost } }) } }\nstruct S { #[cfg(test)] pub(crate) a: u8, b: [u8; { enum DeclaredError { Lost } 1 }] }\nfn gated() {\n    #[cfg(test)]\n    consume({ enum ProbeError { Lost } });\n}\nfn closure() -> S { S { #[cfg(test)] a: |x: u8, y: u8| { enum ClosureError { Lost } x }, b: 0 } }\nfn moved(x: u8) { match x { #[cfg(test)] 0 => move |a: u8, b: u8| { enum MovedError { Lost } a }, _ => drop } }\n",
    ));
    assert_eq!(
        paths(&source),
        [
            "storage::disk::DiskError",
            "storage::disk::CallError",
            "storage::disk::ParenError",
            "storage::disk::ArrayError",
            "storage::disk::LengthError",
            "storage::disk::BodyError",
            "storage::disk::NotError",
            "storage::disk::LateError",
            "storage::disk::LastError",
            "storage::disk::FieldError",
            "storage::disk::ShortError",
            "storage::disk::DeclaredError",
        ]
    );
}

/// Rust 2024 reserves `gen`; the `r#` prefix permits its use as an
/// identifier.
#[test]
fn a_module_declared_with_a_raw_name_gives_its_enums_the_plain_name() {
    let inline = parsed(&files("pub mod r#gen { pub enum InnerRefusal { Busy } }\n"));
    assert_eq!(
        paths(&inline),
        [
            "storage::disk::DiskError",
            "storage::disk::gen::InnerRefusal"
        ]
    );
    let filed = parsed(&tree(&[
        ("storage/mod.rs", "pub mod disk;\npub mod r#gen;\n"),
        ("storage/gen.rs", "pub enum InnerRefusal { Busy }\n"),
    ]));
    assert_eq!(
        paths(&filed),
        ["storage::disk::DiskError", "storage::gen::InnerRefusal"]
    );
}

const BODY: &str = "fn f() -> Result<(), DiskError> { Err(DiskError::Full) }\nfn g() -> DiskError { DiskError::Gone(1) }\n";

fn measured_text() -> String {
    let text = format!("{ENUM}{BODY}");
    export_text(
        &[
            (at(&text, "DiskError::Full", 0), Some(3)),
            (at(&text, "DiskError::Gone", 0), Some(0)),
        ],
        1,
        2,
    )
}

fn measured() -> Register {
    let coverage = Coverage::read(&measured_text()).expect("the fixture export parses");
    measure(
        &parsed(&files(BODY)),
        &coverage,
        "storage",
        None,
        Run::default(),
    )
    .expect("the counts sum within u64")
}

fn with_enum(declaration: &str) -> Source {
    let mut files = files(BODY);
    files.insert(DISK.to_owned(), format!("{declaration}{BODY}"));
    parsed(&files)
}

fn states(register: &Register) -> Vec<(String, String)> {
    register
        .rows
        .iter()
        .map(|row| (row.variant.clone(), row.state.clone()))
        .collect()
}

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(variant, state)| ((*variant).to_owned(), (*state).to_owned()))
        .collect()
}

#[test]
fn measure_places_every_row_and_renders_a_register_that_reads_back() {
    let register = measured();
    assert_eq!(
        states(&register),
        pairs(&[
            ("Full", "reached"),
            ("Gone", "unreached"),
            ("Torn", "unplaced")
        ])
    );
    assert_eq!(register.live.unplaced, 1);
    assert_eq!(
        register.rows[1].reason.as_deref(),
        Some("not-constructed:storage::disk::DiskError")
    );
    assert_eq!(register.reasons.len(), 1);
    assert_eq!(
        Register::read(&register.render()).expect("the render reads"),
        register
    );
}

#[test]
fn a_written_reason_reads_back_and_a_measured_one_renders_without_it() {
    let mut register = measured();
    let measured = register.render();
    assert!(
        !measured.contains("\"kind\"") && !measured.contains("\"missing\""),
        "{measured}"
    );
    register.reasons[0].kind = "step".to_owned();
    register.reasons[0].missing = "No profile removes an object.".to_owned();
    let text = register.render();
    assert!(
        text.contains(r#""kind":"step","missing":"No profile removes an object.","sentence":"""#),
        "{text}"
    );
    assert_eq!(Register::read(&text).expect("the render reads"), register);
}

#[test]
fn sync_adds_an_unmeasured_row_for_a_new_variant() {
    let register = measured();
    let synced = sync(
        &with_enum("pub enum DiskError { Full, Gone(u8), Lost, Torn { at: u8 } }\n"),
        "storage",
        &register,
    );
    assert_eq!(synced.added, ["storage::disk::DiskError::Lost"]);
    assert!(synced.removed.is_empty());
    let lost = &synced.register.rows[2];
    assert_eq!(
        (lost.variant.as_str(), lost.state.as_str()),
        ("Lost", "unmeasured")
    );
    assert_eq!((lost.count, &lost.reason), (None, &None));
    let mut kept = synced.register.rows.clone();
    kept.remove(2);
    assert_eq!(kept, register.rows);
    assert_eq!(synced.register.live, register.live);
    assert_eq!(
        status(&synced.register),
        "unmeasured: 1\nstorage::disk::DiskError::Lost\n"
    );
}

#[test]
fn sync_removes_the_row_of_a_deleted_variant() {
    let register = measured();
    let synced = sync(
        &with_enum("pub enum DiskError { Full, Torn { at: u8 } }\n"),
        "storage",
        &register,
    );
    assert_eq!(synced.removed, ["storage::disk::DiskError::Gone"]);
    assert_eq!(
        states(&synced.register),
        pairs(&[("Full", "reached"), ("Torn", "unplaced")])
    );
    assert_eq!(synced.register.live.unplaced, 1);
    assert_eq!(synced.register.reasons, register.reasons);
}

#[test]
fn sync_lowers_the_live_unplaced_count_when_it_removes_an_unplaced_row() {
    let register = measured();
    let synced = sync(
        &with_enum("pub enum DiskError { Full, Gone(u8) }\n"),
        "storage",
        &register,
    );
    assert_eq!(synced.removed, ["storage::disk::DiskError::Torn"]);
    assert_eq!(synced.register.live.unplaced, 0);
    assert_eq!(synced.register.totals, register.totals);
}

#[test]
fn sync_reads_a_rename_as_a_removal_and_an_addition() {
    let register = measured();
    let synced = sync(
        &with_enum("pub enum DiskError { Full, Missing(u8), Torn { at: u8 } }\n"),
        "storage",
        &register,
    );
    assert_eq!(synced.removed, ["storage::disk::DiskError::Gone"]);
    assert_eq!(synced.added, ["storage::disk::DiskError::Missing"]);
    assert_eq!(
        states(&synced.register),
        pairs(&[
            ("Full", "reached"),
            ("Missing", "unmeasured"),
            ("Torn", "unplaced")
        ])
    );
}

struct Checkout(std::path::PathBuf);

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Checkout {
    /// `new` creates a fresh root with `create_dir`, taking the next free
    /// name, so fixture writes target a tree `new` created.
    fn new(name: &str, source: &BTreeMap<String, String>, register: &Register) -> Self {
        let root = loop {
            let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("reach-{}-{next}-{name}", std::process::id()));
            match std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
                .create(&root)
            {
                Ok(()) => break root,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("{}: {error}", root.display()),
            }
        };
        let checkout = Self(root);
        let root = &checkout.0;
        for (rel, text) in source {
            let path = root.join("crates/kestrike/src").join(rel);
            std::fs::create_dir_all(path.parent().expect("a parent"))
                .expect("the tree is writable");
            std::fs::write(path, text).expect("the source is writable");
        }
        std::fs::create_dir_all(root.join("verification/reach")).expect("the register's directory");
        std::fs::write(
            root.join("verification/reach/storage.json"),
            register.render(),
        )
        .expect("the register");
        checkout
    }

    fn run(&self, arguments: &[&str]) -> Result<String, String> {
        let mut all: Vec<String> = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        all.extend(["--root".to_owned(), self.0.display().to_string()]);
        crate::run(&all)
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("the file is writable");
        path.display().to_string()
    }

    fn register(&self) -> String {
        std::fs::read_to_string(self.0.join("verification/reach/storage.json"))
            .expect("the register")
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_second_sync_changes_nothing() {
    let mut source = files(BODY);
    source.insert(
        DISK.to_owned(),
        format!("pub enum DiskError {{ Full, Lost, Torn {{ at: u8 }} }}\n{BODY}"),
    );
    let checkout = Checkout::new("sync", &source, &measured());
    let first = checkout.run(&["sync", "storage"]).expect("sync exits 0");
    assert!(first.contains("1 added, 1 removed"), "{first}");
    let after_first = checkout.register();
    let second = checkout.run(&["sync", "storage"]).expect("sync exits 0");
    assert!(second.contains("0 added, 0 removed"), "{second}");
    assert_eq!(checkout.register(), after_first);
    let status = checkout
        .run(&["sync", "storage", "--status"])
        .expect("the status exits 0");
    assert_eq!(status, "unmeasured: 1\nstorage::disk::DiskError::Lost\n");
}

#[test]
fn compare_prints_each_changed_row_and_exits_zero() {
    let checkout = Checkout::new("compare", &files(BODY), &measured());
    let same = checkout.file("same.json", &measured_text());
    assert_eq!(
        checkout.run(&["compare", "storage", "--export", &same]),
        Ok(String::new())
    );
    let text = format!("{ENUM}{BODY}");
    let changed = checkout.file(
        "changed.json",
        &export_text(
            &[
                (at(&text, "DiskError::Full", 0), Some(3)),
                (at(&text, "DiskError::Gone", 0), Some(6)),
            ],
            1,
            2,
        ),
    );
    let before = checkout.register();
    assert_eq!(
        checkout.run(&["compare", "storage", "--export", &changed]),
        Ok("storage::disk::DiskError::Gone: unreached 0 -> reached 6\n".to_owned())
    );
    assert_eq!(checkout.register(), before);
    let counted = checkout.file(
        "counted.json",
        &export_text(
            &[
                (at(&text, "DiskError::Full", 0), Some(5)),
                (at(&text, "DiskError::Gone", 0), Some(0)),
            ],
            1,
            2,
        ),
    );
    assert_eq!(
        checkout.run(&["compare", "storage", "--export", &counted]),
        Ok("storage::disk::DiskError::Full: reached 3 -> reached 5\n".to_owned())
    );
    assert_eq!(checkout.register(), before);
}

#[test]
fn compare_prints_a_row_that_only_one_side_holds() {
    let mut source = files(BODY);
    source.insert(
        DISK.to_owned(),
        format!("pub enum DiskError {{ Full, Lost, Torn {{ at: u8 }} }}\n{BODY}"),
    );
    let checkout = Checkout::new("absent", &source, &measured());
    let same = checkout.file("same.json", &measured_text());
    assert_eq!(
        checkout.run(&["compare", "storage", "--export", &same]),
        Ok(
            "storage::disk::DiskError::Gone: unreached 0 -> absent\nstorage::disk::DiskError::Lost: absent -> unplaced\n"
                .to_owned()
        )
    );
}

fn placed_body(
    body: &str,
    variant: &str,
    segments: &[(&str, usize, Option<u64>)],
    entered: u64,
) -> crate::mapping::Placement {
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let segments: Vec<((usize, usize), Option<u64>)> = segments
        .iter()
        .map(|(needle, nth, count)| (at(&text, needle, *nth), *count))
        .collect();
    placed(&source, variant, &export(&segments, entered, 1))
}

#[test]
fn an_uncounted_site_in_a_function_that_ran_leaves_its_variant_unplaced() {
    let body = "fn f() -> DiskError { DiskError::Full }\nfn g(x: Result<u8, u8>) -> Result<u8, DiskError> { x.map_err(|_| DiskError::Full) }\n";
    let placement = placed_body(
        body,
        "Full",
        &[
            ("DiskError::Full", 0, Some(0)),
            ("DiskError::Full", 1, None),
        ],
        1,
    );
    assert_eq!(
        (placement.state, placement.cause),
        (State::Unplaced, Some(Cause::NoRegion))
    );
    let placement = placed_body(
        body,
        "Full",
        &[
            ("DiskError::Full", 0, Some(0)),
            ("DiskError::Full", 1, None),
        ],
        0,
    );
    assert_eq!(placement.state, State::Unreached);
}

#[test]
fn an_eager_argument_keeps_its_chain_through_an_if_and_loses_it_inside_another_call() {
    let body = "fn f(x: Option<u8>, c: bool) -> Result<u8, DiskError> { let v = x.ok_or(if c { DiskError::Full } else { DiskError::Gone(0) })?; Ok(v) }\nfn g(x: Option<u8>) -> Result<u8, DiskError> { let v = wrap(x.ok_or(DiskError::Torn { at: 0 }))?; Ok(v) }\n";
    let segments = [
        ("DiskError::Full", 0, Some(4)),
        ("DiskError::Gone", 0, Some(5)),
        ("DiskError::Torn", 0, Some(9)),
        ("?;", 0, Some(0)),
        ("?;", 1, Some(3)),
    ];
    for variant in ["Full", "Gone"] {
        let placement = placed_body(body, variant, &segments, 1);
        assert_eq!(
            (placement.state, placement.measured),
            (State::Unreached, Some(Measured::NotConstructed)),
            "{variant}"
        );
    }
    let torn = placed_body(body, "Torn", &segments, 1);
    assert_eq!(
        (torn.state, torn.cause),
        (State::Unplaced, Some(Cause::Unplaceable))
    );
}

#[test]
fn a_function_value_whose_question_mark_never_returned_is_unreached_and_counts_sum() {
    let body = "fn f(x: Result<u8, u8>) -> Result<u8, DiskError> { let v = x.map_err(DiskError::Gone)?; Ok(v) }\nfn g() -> DiskError { DiskError::Gone(1) }\nfn h() -> DiskError { DiskError::Gone(2) }\n";
    let unreached = placed_body(
        body,
        "Gone",
        &[
            ("?;", 0, Some(0)),
            ("DiskError::Gone", 1, Some(0)),
            ("DiskError::Gone", 2, Some(0)),
        ],
        1,
    );
    assert_eq!(unreached.state, State::Unreached);
    let reached = placed_body(
        body,
        "Gone",
        &[
            ("?;", 0, Some(0)),
            ("DiskError::Gone", 1, Some(2)),
            ("DiskError::Gone", 2, Some(3)),
        ],
        1,
    );
    assert_eq!((reached.state, reached.count), (State::Reached, 5));
}

#[test]
fn a_site_after_a_wide_character_maps_to_its_byte_column() {
    let body = "fn f() -> DiskError { let _s = \"\u{b5}\u{b5}\u{b5}\"; DiskError::Full }\n";
    let placement = placed_body(
        body,
        "Full",
        &[("let", 0, Some(0)), ("DiskError::Full", 0, Some(1))],
        1,
    );
    assert_eq!((placement.state, placement.count), (State::Reached, 1));
}

#[test]
fn statics_associated_constants_and_every_comparison_are_no_reach() {
    let body = "static MORE: [DiskError; 1] = [DiskError::Full];\nimpl DiskError { const FIRST: Self = DiskError::Full; }\nfn f(e: &DiskError) -> bool { assert_eq!(*e, DiskError::Full); *e != DiskError::Full }\n";
    let source = parsed(&files(body));
    let forms: Vec<Form> = source.sites_of(0, "Full").map(|site| site.form).collect();
    assert_eq!(
        forms,
        [Form::Table, Form::Table, Form::Compare, Form::Compare]
    );
}

#[test]
fn a_same_named_enum_resolves_by_module_file_and_hint_and_an_unresolved_path_is_refused() {
    let enumeration = "pub enum Refusal { Busy, Gone }\n";
    let files = BTreeMap::from([
        ("mod.rs".to_owned(), "pub mod storage;\n".to_owned()),
        (
            "storage/mod.rs".to_owned(),
            "pub mod a;\npub mod b;\npub mod c;\n".to_owned(),
        ),
        (
            "storage/a.rs".to_owned(),
            format!("{enumeration}fn fa() -> Refusal {{ Refusal::Busy }}\n"),
        ),
        (
            "storage/b.rs".to_owned(),
            format!("{enumeration}fn fb() -> super::a::Refusal {{ super::a::Refusal::Gone }}\n"),
        ),
        (
            "storage/c.rs".to_owned(),
            "fn fc() { let _ = super::b::Refusal::Busy; let _ = b::Refusal::Gone; }\n".to_owned(),
        ),
    ]);
    let source = parsed(&files);
    let owners: Vec<(String, String, String)> = source
        .sites
        .iter()
        .map(|site| {
            (
                site.function.clone(),
                site.variant.clone(),
                source.enums[site.owner].path.clone(),
            )
        })
        .collect();
    let owner = |function: &str, variant: &str, path: &str| {
        (function.to_owned(), variant.to_owned(), path.to_owned())
    };
    assert_eq!(
        owners,
        [
            owner("fa", "Busy", "storage::a::Refusal"),
            owner("fb", "Gone", "storage::a::Refusal"),
            owner("fc", "Busy", "storage::b::Refusal"),
            owner("fc", "Gone", "storage::b::Refusal"),
        ]
    );
    let mut ambiguous = files.clone();
    ambiguous.insert(
        "storage/c.rs".to_owned(),
        "fn fd() { let _ = Refusal::Busy; }\n".to_owned(),
    );
    assert_eq!(
        parsed(&ambiguous).ambiguous,
        ["storage/c.rs:1: Refusal::Busy"]
    );
    let checkout = Checkout::new("ambiguous", &ambiguous, &Register::default());
    let refused = checkout
        .run(&["sync", "storage"])
        .expect_err("sync refuses");
    assert!(
        refused.contains("storage/c.rs:1: Refusal::Busy"),
        "{refused}"
    );
}

#[test]
fn a_later_measurement_keeps_reason_rows_and_reasons_that_still_fit() {
    let mut earlier = measured();
    let grouped = "not-constructed:hand-grouped";
    earlier.reasons[0].id = grouped.to_owned();
    earlier.rows[1].reason = Some(grouped.to_owned());
    earlier.reasons[0].sentence = "written by hand".to_owned();
    earlier.reasons[0].kind = "fault".to_owned();
    earlier.reasons[0].missing = "written by hand".to_owned();
    let source = parsed(&files(BODY));
    let again = measure(
        &source,
        &Coverage::read(&measured_text()).expect("the export parses"),
        "storage",
        Some(&earlier),
        Run::default(),
    )
    .expect("the counts sum within u64");
    assert_eq!(again.reasons, earlier.reasons);
    assert_eq!(again.rows, earlier.rows);
    let text = format!("{ENUM}{BODY}");
    let unrun = export(&[(at(&text, "DiskError::Full", 0), Some(0))], 0, 0);
    let moved = measure(&source, &unrun, "storage", Some(&earlier), Run::default())
        .expect("the counts sum within u64");
    assert_eq!(moved.reasons[0], earlier.reasons[0]);
    assert_eq!(
        moved.rows[1].reason.as_deref(),
        Some("file-not-run:storage/disk.rs")
    );
    assert_eq!(moved.reasons.len(), 2);
}

#[test]
fn a_later_measurement_leaves_no_row_unmeasured() {
    let declaration = "pub enum DiskError { Full, Gone(u8), Lost, Torn { at: u8 } }\n";
    let body = format!("{BODY}fn h() -> DiskError {{ DiskError::Lost }}\n");
    let mut files = files(&body);
    files.insert(DISK.to_owned(), format!("{declaration}{body}"));
    let source = parsed(&files);
    let synced = sync(&source, "storage", &measured()).register;
    assert_eq!(
        status(&synced),
        "unmeasured: 1\nstorage::disk::DiskError::Lost\n"
    );
    let text = format!("{declaration}{body}");
    let coverage = export(&[(at(&text, "DiskError::Lost", 0), Some(2))], 1, 3);
    let remeasured = measure(&source, &coverage, "storage", Some(&synced), Run::default())
        .expect("the counts sum within u64");
    assert_eq!(status(&remeasured), "unmeasured: 0\n");
    assert_eq!(remeasured.rows[2].state, "reached");
}

#[test]
fn sync_lowers_the_header_count_and_never_counts_anew() {
    let mut register = measured();
    register.live.unplaced = 5;
    let kept = sync(
        &with_enum("pub enum DiskError { Gone(u8), Torn { at: u8 } }\n"),
        "storage",
        &register,
    );
    assert_eq!(kept.register.live.unplaced, 5);
    let lowered = sync(
        &with_enum("pub enum DiskError { Full, Gone(u8) }\n"),
        "storage",
        &register,
    );
    assert_eq!(lowered.register.live.unplaced, 4);
}

#[test]
fn the_tool_digest_covers_every_source_file() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = 0;
    for entry in std::fs::read_dir(directory).expect("the source directory") {
        let entry = entry.expect("a directory entry");
        assert!(entry.file_type().expect("a file type").is_file());
        if entry.file_name() == "tests.rs" {
            continue;
        }
        let bytes = std::fs::read(entry.path()).expect("a source file");
        assert!(
            crate::SOURCES.contains(&bytes.as_slice()),
            "{:?}",
            entry.file_name()
        );
        files += 1;
    }
    assert_eq!(files + 2, crate::SOURCES.len());
}

fn tree(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut files = BTreeMap::from([
        ("mod.rs".to_owned(), "pub mod storage;\n".to_owned()),
        ("storage/mod.rs".to_owned(), "pub mod disk;\n".to_owned()),
        (DISK.to_owned(), ENUM.to_owned()),
    ]);
    for (rel, text) in entries {
        files.insert((*rel).to_owned(), (*text).to_owned());
    }
    files
}

fn paths(source: &Source) -> Vec<String> {
    source
        .enums
        .iter()
        .map(|declared| declared.path.clone())
        .collect()
}

#[test]
fn a_path_module_that_re_enters_its_file_is_refused() {
    let found = refused(&tree(&[(DISK, "#[path = \"disk.rs\"] mod again;\n")]));
    assert!(found.contains("storage/disk.rs"), "{found}");
    let found = refused(&tree(&[
        ("storage/mod.rs", "#[path = \"a.rs\"] mod a;\n"),
        ("storage/a.rs", "#[path = \"mod.rs\"] mod back;\n"),
    ]));
    assert!(found.contains("storage/mod.rs"), "{found}");
}

#[test]
fn a_path_module_resolves_inside_the_root_and_refuses_one_that_leaves_it() {
    let source = parsed(&tree(&[
        (
            "storage/mod.rs",
            "#[path = \"impl/../disk_impl.rs\"] pub mod disk;\n",
        ),
        ("storage/disk_impl.rs", ENUM),
    ]));
    assert_eq!(paths(&source), ["storage::disk::DiskError"]);
    for target in ["../../x.rs", "/x.rs", "../../../crates/kestrike/src/x.rs"] {
        let files = tree(&[
            (
                "storage/mod.rs",
                &format!("#[path = {target:?}] pub mod disk;\n"),
            ),
            ("x.rs", ENUM),
        ]);
        let found = refused(&files);
        assert!(
            found.contains("outside the source root"),
            "{target}: {found}"
        );
    }
    let inline = tree(&[(
        "storage/mod.rs",
        "mod outer { #[path = \"x.rs\"] mod disk; }\n",
    )]);
    assert!(refused(&inline).contains("inside an inline module"));
}

#[test]
fn a_cfg_attr_path_is_refused_unless_its_predicate_is_false() {
    for attribute in [
        "#[cfg_attr(unix, path = \"other.rs\")]",
        "#[cfg_attr(all(), cfg_attr(unix, path = \"other.rs\"))]",
        "#[cfg_attr(unix, allow(dead_code), path = \"other.rs\")]",
    ] {
        let files = tree(&[
            ("storage/mod.rs", &format!("{attribute}\npub mod disk;\n")),
            ("storage/other.rs", "pub enum OtherError { A }\n"),
        ]);
        assert!(refused(&files).contains("cfg_attr"), "{attribute}");
    }
    let files = tree(&[(
        "storage/mod.rs",
        "#[cfg_attr(test, path = \"other.rs\")]\npub mod disk;\n",
    )]);
    assert_eq!(paths(&parsed(&files)), ["storage::disk::DiskError"]);
}

#[test]
fn a_module_file_that_cannot_be_read_or_has_two_layouts_is_refused() {
    let files = tree(&[("storage/disk/mod.rs", "pub enum OtherError { A }\n")]);
    let found = parse(&|rel: &str| {
        if rel == DISK {
            Err(format!("{rel}: permission denied"))
        } else {
            Ok(files.get(rel).cloned())
        }
    })
    .expect_err("an unreadable file is refused");
    assert!(found.contains("permission denied"), "{found}");
    assert!(refused(&files).contains("two files for `mod disk`"));
    let mut nested = files.clone();
    nested.remove(DISK);
    assert_eq!(paths(&parsed(&nested)), ["storage::disk::OtherError"]);
}

#[test]
fn an_inner_test_gate_excludes_its_file_and_raw_names_lose_their_prefix() {
    let files = tree(&[
        ("storage/mod.rs", "pub mod disk;\npub mod probe;\n"),
        (
            "storage/probe.rs",
            "#![cfg(test)]\npub enum ProbeError { A }\n",
        ),
        (
            DISK,
            "pub enum DiskError { r#Type, Full }\nfn f() -> DiskError { DiskError::r#Type }\n",
        ),
    ]);
    let source = parsed(&files);
    assert_eq!(paths(&source), ["storage::disk::DiskError"]);
    let names: Vec<&str> = source.enums[0]
        .variants
        .iter()
        .map(|v| v.name.as_str())
        .collect();
    assert_eq!(names, ["Type", "Full"]);
    assert_eq!(source.sites_of(0, "Type").count(), 1);
}

#[test]
fn a_cfg_split_variant_keeps_one_row_and_two_shapes_or_two_declarations_are_refused() {
    let split = "pub enum DiskError { #[cfg(unix)] Full(u8), #[cfg(not(unix))] Full(u16), Gone(u8), Torn { at: u8 } }\n";
    let source = with_enum(split);
    let names: Vec<&str> = source.enums[0]
        .variants
        .iter()
        .map(|v| v.name.as_str())
        .collect();
    assert_eq!(names, ["Full", "Gone", "Torn"]);
    let register = measured();
    let once = sync(&source, "storage", &register);
    assert!(once.added.is_empty() && once.removed.is_empty());
    assert_eq!(once.register, register);
    let twice = sync(&source, "storage", &once.register);
    assert_eq!(twice.register.render(), register.render());
    let shapes = "pub enum DiskError { #[cfg(unix)] Full, #[cfg(not(unix))] Full(u8) }\n";
    let found = refused(&tree(&[(DISK, shapes)]));
    assert!(found.contains("two shapes"), "{found}");
    let whole = "#[cfg(unix)]\npub enum DiskError { Full }\n#[cfg(not(unix))]\npub enum DiskError { Full }\n";
    assert!(refused(&tree(&[(DISK, whole)])).contains("declared twice"));
    let local = "fn a() { enum LocalError { Busy } let _ = LocalError::Busy; }\nfn b() { enum LocalError { Busy } }\n";
    let found = refused(&tree(&[(DISK, &format!("{ENUM}{local}"))]));
    assert!(
        found.contains("storage::disk::LocalError is declared twice"),
        "{found}"
    );
}

fn owners(source: &Source) -> Vec<(String, String, String)> {
    source
        .sites
        .iter()
        .map(|site| {
            (
                site.function.clone(),
                source.enums[site.owner].path.clone(),
                site.variant.clone(),
            )
        })
        .collect()
}

fn owner(function: &str, path: &str, variant: &str) -> (String, String, String) {
    (function.to_owned(), path.to_owned(), variant.to_owned())
}

#[test]
fn an_import_binds_only_in_its_own_scope() {
    let body = "pub enum WriteError { Busy, Full }\n\
fn a() { use DiskError::Full as V; let _ = V; }\n\
fn b() { use WriteError::Busy as V; let _ = V; }\n\
mod inner { fn c() { let _ = V; } }\n\
trait T { #[cfg(test)] fn t() { use DiskError::Gone as Full; } }\n\
fn d() -> DiskError { use DiskError::*; Full }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    assert_eq!(
        owners(&source),
        [
            owner("a", "storage::disk::DiskError", "Full"),
            owner("b", "storage::disk::WriteError", "Busy"),
            owner("d", "storage::disk::DiskError", "Full"),
        ]
    );
    let coverage = export(
        &[
            (at(&text, "= V;", 0), Some(2)),
            (at(&text, "= V;", 1), Some(0)),
        ],
        1,
        1,
    );
    let full: Vec<_> = source.sites_of(0, "Full").take(1).collect();
    assert_eq!(
        place(&full, &coverage).expect("a sum").state,
        State::Reached
    );
    let busy: Vec<_> = source.sites_of(1, "Busy").collect();
    assert_eq!(
        place(&busy, &coverage).expect("a sum").state,
        State::Unreached
    );
}

#[test]
fn a_qualifier_resolves_through_a_re_export_below_it_and_a_tie_between_unlisted_enums_passes() {
    let files = BTreeMap::from([
        ("mod.rs".to_owned(), "pub mod storage;\nmod sim;\n".to_owned()),
        ("storage/mod.rs".to_owned(), "pub mod a;\npub mod b;\n".to_owned()),
        ("storage/a/mod.rs".to_owned(), "mod table;\npub use table::Refusal;\n".to_owned()),
        ("storage/a/table.rs".to_owned(), "pub enum Refusal { Busy }\n".to_owned()),
        (
            "storage/b.rs".to_owned(),
            "pub enum Refusal { Busy }\nfn fb() { let _ = super::a::Refusal::Busy; let _ = crate::sim::Refusal::Busy; }\n".to_owned(),
        ),
        (
            "sim.rs".to_owned(),
            "mod x { pub enum HostRefusal { Busy } }\nmod y { pub enum HostRefusal { Busy } }\nfn s() { let _ = HostRefusal::Busy; }\n".to_owned(),
        ),
    ]);
    let source = parsed(&files);
    let listed: Vec<_> = owners(&source)
        .into_iter()
        .filter(|(_, path, _)| path.starts_with("storage"))
        .collect();
    assert_eq!(listed, [owner("fb", "storage::a::table::Refusal", "Busy")]);
    assert_eq!(
        source.ambiguous,
        ["storage/b.rs:2: crate::sim::Refusal::Busy"]
    );
}

/// With one crate enum of a name, a path that names it and its variant is
/// a site of that enum whatever the qualifier names, written or imported.
#[test]
fn a_path_to_the_one_enum_of_its_name_is_a_site_whatever_its_qualifier() {
    let body = "fn f() { let _ = foreign::DiskError::Full; }\nfn g() { use other_crate::io::DiskError; let _ = DiskError::Full; }\n";
    let source = parsed(&files(body));
    assert_eq!(
        owners(&source),
        [
            owner("f", "storage::disk::DiskError", "Full"),
            owner("g", "storage::disk::DiskError", "Full"),
        ]
    );
    assert!(source.ambiguous.is_empty());
}

#[test]
fn a_site_in_a_trait_default_method_names_the_trait() {
    let body = "trait Probe { fn probe(&self) -> DiskError { DiskError::Full } }\n";
    let source = parsed(&files(body));
    assert_eq!(
        owners(&source),
        [owner("Probe::probe", "storage::disk::DiskError", "Full")]
    );
}

#[test]
fn an_inner_question_mark_inside_an_eager_argument_ends_its_own_chain() {
    let body = "fn f(x: Option<u8>, y: Option<u8>, c: bool) -> Result<u8, DiskError> { let v = x.ok_or(if c { y.ok_or(DiskError::Full)?; DiskError::Torn { at: 0 } } else { DiskError::Gone(0) })?; Ok(v) }\n";
    let segments = [
        ("DiskError::Full", 0, Some(7)),
        ("DiskError::Torn", 0, Some(5)),
        ("DiskError::Gone", 0, Some(5)),
        ("?;", 0, Some(3)),
        ("?;", 1, Some(0)),
    ];
    let full = placed_body(body, "Full", &segments, 1);
    assert_eq!((full.state, full.count), (State::Reached, 3));
    for variant in ["Torn", "Gone"] {
        assert_eq!(
            placed_body(body, variant, &segments, 1).state,
            State::Unreached,
            "{variant}"
        );
    }
}

#[test]
fn a_zero_question_mark_proves_only_an_error_path_closure_never_ran() {
    for body in [
        "fn f(r: Result<u8, u8>) -> Result<DiskError, u8> { let v = r.map(|_| DiskError::Full)?; Ok(v) }\n",
        "fn f() -> Result<u8, u8> { let v = wrap(DiskError::Full)?; Ok(v) }\n",
    ] {
        let placement = placed_body(
            body,
            "Full",
            &[("DiskError::Full", 0, None), ("?;", 0, Some(0))],
            1,
        );
        assert_eq!(
            (placement.state, placement.cause),
            (State::Unplaced, Some(Cause::NoRegion)),
            "{body}"
        );
    }
    for body in [
        "fn f(x: Result<u8, u8>) -> Result<u8, DiskError> { let v = x.map_err(|_| { DiskError::Full })?; Ok(v) }\n",
        "fn f(x: Result<u8, u8>) -> Result<u8, DiskError> { let v = x.map_err(|e| match e { 0 => DiskError::Full, _ => wrap(DiskError::Full) })?; Ok(v) }\n",
        "fn f(x: Option<u8>) -> Result<u8, DiskError> { let v = x.ok_or_else(|| DiskError::Full)?; Ok(v) }\n",
    ] {
        let segments = [("DiskError::Full", 0, None), ("?;", 0, Some(0))];
        let placement = placed_body(body, "Full", &segments, 1);
        assert_eq!(
            (placement.state, placement.measured),
            (State::Unreached, Some(Measured::NotConstructed)),
            "{body}"
        );
    }
}

#[test]
fn a_constructor_that_returns_through_its_question_mark_in_a_comparison_is_counted() {
    let body = "fn f(x: Result<u8, u8>) -> Result<bool, DiskError> { Ok(x.map_err(DiskError::Gone)? == 1) }\nfn g(x: Option<u8>) -> Result<(), DiskError> { assert_eq!(x.ok_or(DiskError::Full)?, 1); Ok(()) }\nfn h(e: &DiskError) -> bool { *e == DiskError::Torn { at: 0 } }\n";
    let source = parsed(&files(body));
    let forms: Vec<Form> = source.sites.iter().map(|site| site.form).collect();
    assert_eq!(forms, [Form::Value, Form::Eager, Form::Compare]);
    for (variant, question) in [("Gone", "? =="), ("Full", "?, 1")] {
        for count in [0, 4] {
            let placement = placed_body(
                body,
                variant,
                &[
                    (&format!("DiskError::{variant}"), 0, Some(9)),
                    (question, 0, Some(count)),
                ],
                1,
            );
            assert_eq!(placement.count, count, "{variant}");
        }
    }
}

#[test]
fn a_shared_question_mark_never_credits_an_untaken_or_repeated_branch() {
    let body = "fn f(x: Option<u8>, c: bool) -> Result<u8, DiskError> { let v = x.ok_or(if c { DiskError::Full } else { DiskError::Gone(0) })?; Ok(v) }\nfn g(x: Option<u8>, c: bool) -> Result<u8, DiskError> { let v = x.ok_or(if c { DiskError::Torn { at: 0 } } else { DiskError::Torn { at: 1 } })?; Ok(v) }\n";
    let segments = [
        ("DiskError::Full", 0, Some(0)),
        ("DiskError::Gone", 0, Some(5)),
        ("DiskError::Torn", 0, Some(2)),
        ("DiskError::Torn", 1, Some(3)),
        ("?;", 0, Some(3)),
        ("?;", 1, Some(1)),
    ];
    let full = placed_body(body, "Full", &segments, 1);
    assert_eq!(
        (full.state, full.measured),
        (State::Unreached, Some(Measured::NotConstructed))
    );
    for variant in ["Gone", "Torn"] {
        let placement = placed_body(body, variant, &segments, 1);
        assert_eq!(
            (placement.state, placement.cause),
            (State::Unplaced, Some(Cause::Unplaceable)),
            "{variant}"
        );
    }
}

type Segments<'a> = &'a [((usize, usize), Option<u64>)];

type Span = ((usize, usize), (usize, usize), u64);

/// `custom` builds an export from file records (segments and covered lines)
/// and function records (start, end and entry count), all in `DISK`.
fn custom(files: &[(Segments, u64)], functions: &[Span]) -> Coverage {
    let name = format!("/w/crates/kestrike/src/{DISK}");
    let files: Vec<String> = files
        .iter()
        .map(|(segments, covered)| {
            let segments: Vec<String> = segments.iter().map(segment).collect();
            format!(
                r#"{{"filename":"{name}","segments":[{}],"summary":{{"lines":{{"covered":{covered}}}}}}}"#,
                segments.join(",")
            )
        })
        .collect();
    let functions: Vec<String> = functions
        .iter()
        .map(|&(start, end, count)| {
            let region = code_region(start, end, count);
            format!(r#"{{"count":{count},"regions":[{region}],"filenames":["{name}"]}}"#)
        })
        .collect();
    let text = format!(
        r#"{{"data":[{{"files":[{}],"functions":[{}]}}]}}"#,
        files.join(","),
        functions.join(",")
    );
    Coverage::read(&text).expect("the custom export parses")
}

#[test]
fn coverage_predicates_hold_at_counts_whose_sum_overflows() {
    let body = "fn f() -> DiskError { DiskError::Full }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let site = at(&text, "DiskError::Full", 0);
    let spans = [((1, 1), (9, 1), u64::MAX), ((2, 1), (2, 99), 1)];
    let uncounted = custom(&[(&[(site, None)], 1)], &spans);
    let placement = placed(&source, "Full", &uncounted);
    assert_eq!(
        (placement.state, placement.cause),
        (State::Unplaced, Some(Cause::NoRegion))
    );
    let summaries = custom(
        &[(&[(site, Some(0))], u64::MAX), (&[], 1)],
        &[((2, 1), (2, 99), 0)],
    );
    let placement = placed(&source, "Full", &summaries);
    assert_eq!(placement.measured, Some(Measured::FunctionNotEntered));
}

#[test]
fn each_site_reads_the_entry_count_of_its_own_function_and_an_earlier_segment() {
    let body =
        "fn f() -> u8 { 1 }\nfn g() -> DiskError {\n    let _ = 1;\n    DiskError::Full\n}\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let f = (at(&text, "fn f", 0), at(&text, "}\nfn g", 0));
    let g = (at(&text, "fn g", 0), (6, 2));
    let segments = [
        (at(&text, "fn g", 0), Some(4)),
        (at(&text, "}\n", 1), Some(0)),
    ];
    let coverage = custom(&[(&segments, 2)], &[(f.0, f.1, 3), (g.0, g.1, 0)]);
    let placement = placed(&source, "Full", &coverage);
    assert_eq!((placement.state, placement.count), (State::Reached, 4));
    let unentered = custom(
        &[(&[(at(&text, "fn g", 0), Some(0))], 2)],
        &[(f.0, f.1, 3), (g.0, g.1, 0)],
    );
    let placement = placed(&source, "Full", &unentered);
    assert_eq!(placement.measured, Some(Measured::FunctionNotEntered));
}

#[test]
fn a_function_not_entered_reason_lists_the_functions_of_every_row() {
    let body =
        "fn f() -> DiskError { DiskError::Full }\nfn g() -> DiskError { DiskError::Gone(1) }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let coverage = custom(
        &[(
            &[
                (at(&text, "DiskError::Full", 0), Some(0)),
                (at(&text, "DiskError::Gone", 0), Some(0)),
            ],
            1,
        )],
        &[((1, 1), (1, 99), 1), ((2, 1), (3, 99), 0)],
    );
    let register = measure(&source, &coverage, "storage", None, Run::default())
        .expect("the counts sum within u64");
    assert_eq!(register.reasons.len(), 1);
    let functions: Vec<&str> = register.reasons[0]
        .functions
        .iter()
        .map(|(_, f)| f.as_str())
        .collect();
    assert_eq!(functions, ["f", "g"]);
    assert_eq!(register.rows[0].reason, register.rows[1].reason);
}

#[test]
fn a_later_measurement_keeps_a_reason_id_it_would_not_compute() {
    let mut earlier = measured();
    earlier.reasons[0].id = "not-constructed:by-hand".to_owned();
    earlier.rows[1].reason = Some("not-constructed:by-hand".to_owned());
    let again = measure(
        &parsed(&files(BODY)),
        &Coverage::read(&measured_text()).expect("the export parses"),
        "storage",
        Some(&earlier),
        Run::default(),
    )
    .expect("the counts sum within u64");
    assert_eq!(
        again.rows[1].reason.as_deref(),
        Some("not-constructed:by-hand")
    );
    assert_eq!(again.reasons, earlier.reasons);
}

#[test]
fn measure_counts_each_state_and_class_in_the_header() {
    let totals = measured().totals;
    assert_eq!(
        (
            totals.rows,
            totals.reached,
            totals.unreached,
            totals.unplaced
        ),
        (3, 1, 1, 1)
    );
    assert_eq!(
        (
            totals.file_not_run,
            totals.function_not_entered,
            totals.not_constructed
        ),
        (0, 0, 1)
    );
}

#[test]
fn the_register_reader_refuses_a_repeated_row_and_fields_that_do_not_fit_the_state() {
    let text = measured().render();
    assert!(Register::read(&text).is_ok());
    let full = r#"{"enum":"storage::disk::DiskError","variant":"Full","sites":[["storage/disk.rs","f","path"]],"state":"reached","count":3}"#;
    for broken in [
        text.replace(full, &format!("{full},\n{full}")),
        text.replace(r#""state":"reached","count":3"#, r#""state":"reached""#),
        text.replace(r#""state":"reached""#, r#""state":"umeasured""#),
        text.replace(r#""cause":"no-site""#, r#""cause":"none""#),
    ] {
        assert_ne!(broken, text);
        assert!(Register::read(&broken).is_err(), "{broken}");
    }
}

#[test]
fn a_failed_register_write_leaves_the_register_as_it_was() {
    let checkout = Checkout::new("publish", &files(BODY), &measured());
    let path = checkout.0.join("verification/reach/storage.json");
    let before = checkout.register();
    let failed = crate::publish(&path, "{}", |file, bytes| {
        std::io::Write::write_all(file, &bytes[..1])?;
        Err(std::io::Error::other("the disk is full"))
    });
    assert!(
        failed
            .expect_err("the write fails")
            .contains("the disk is full")
    );
    assert_eq!(checkout.register(), before);
    let left: Vec<_> = std::fs::read_dir(path.parent().expect("a parent"))
        .expect("the directory")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(left, ["storage.json"]);
}

#[test]
fn measure_writes_a_new_register_with_the_tool_digest_and_sites_lists_each_site() {
    let checkout = Checkout::new("measure", &files(BODY), &measured());
    std::fs::remove_file(checkout.0.join("verification/reach/storage.json")).expect("remove");
    let export = checkout.file("export.json", &measured_text());
    let run = checkout.file(
        "run.json",
        &serde_json::to_string(&Run::default()).expect("a run"),
    );
    let out = checkout
        .run(&["measure", "storage", "--export", &export, "--run", &run])
        .expect("measure exits 0");
    assert!(
        out.ends_with(": 3 rows, 1 reached, 1 unreached, 1 unplaced\n"),
        "{out}"
    );
    let written = Register::read(&checkout.register()).expect("the register reads");
    assert_eq!(written.run.tool, crate::digest());
    assert_eq!(written.rows, measured().rows);
    let sites = checkout.run(&["sites", "storage"]).expect("sites exits 0");
    assert!(
        sites
            .contains("storage::disk::DiskError (storage/disk.rs)\n  Full\n    storage/disk.rs:2:"),
        "{sites}"
    );
}

/// A function record's regions, as `llvm-cov export` writes them: start
/// line and column, end line and column, count, file id, expanded file id
/// and kind.
type Regions<'a> = &'a [[u64; 8]];

/// `raw` builds an export from file records (path, segments, covered lines)
/// and function records (path, regions, entry count).
fn raw(files: &[(&str, Segments, u64)], functions: &[(&str, Regions, u64)]) -> Coverage {
    let name = |rel: &str| format!("/w/crates/kestrike/src/{rel}");
    let files: Vec<String> = files
        .iter()
        .map(|(rel, segments, covered)| {
            let segments: Vec<String> = segments.iter().map(segment).collect();
            format!(
                r#"{{"filename":"{}","segments":[{}],"summary":{{"lines":{{"covered":{covered}}}}}}}"#,
                name(rel),
                segments.join(",")
            )
        })
        .collect();
    let functions: Vec<String> = functions
        .iter()
        .map(|(rel, regions, count)| {
            let regions: Vec<String> = regions
                .iter()
                .map(|region| format!("{region:?}").replace(' ', ""))
                .collect();
            format!(
                r#"{{"count":{count},"regions":[{}],"filenames":["{}"]}}"#,
                regions.join(","),
                name(rel)
            )
        })
        .collect();
    let text = format!(
        r#"{{"data":[{{"files":[{}],"functions":[{}]}}]}}"#,
        files.join(","),
        functions.join(",")
    );
    Coverage::read(&text).expect("the raw export parses")
}

/// One code region over lines 1 to 999.
const WHOLE: [u64; 8] = [1, 1, 999, 1, 0, 0, 0, 0];

#[test]
fn a_file_ran_when_any_of_its_records_has_a_covered_line() {
    let body = "fn f() -> DiskError { DiskError::Full }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let site: Segments = &[(at(&text, "DiskError::Full", 0), Some(0))];
    for covered in [[3, 0], [0, 3]] {
        let coverage = raw(
            &[(DISK, site, covered[0]), (DISK, &[], covered[1])],
            &[(DISK, &[WHOLE], 0)],
        );
        let placement = placed(&source, "Full", &coverage);
        assert_eq!(
            placement.measured,
            Some(Measured::FunctionNotEntered),
            "{covered:?}"
        );
    }
}

#[test]
fn a_function_is_entered_when_any_of_its_instantiations_ran() {
    let body = "fn f<T>() -> DiskError { DiskError::Full }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let site: Segments = &[(at(&text, "DiskError::Full", 0), Some(0))];
    for counts in [[0, 2], [2, 0]] {
        let coverage = raw(
            &[(DISK, site, 1)],
            &[(DISK, &[WHOLE], counts[0]), (DISK, &[WHOLE], counts[1])],
        );
        let placement = placed(&source, "Full", &coverage);
        assert_eq!(
            placement.measured,
            Some(Measured::NotConstructed),
            "{counts:?}"
        );
    }
    let unentered = raw(
        &[(DISK, site, 1)],
        &[(DISK, &[WHOLE], 0), (DISK, &[WHOLE], 0)],
    );
    assert_eq!(
        placed(&source, "Full", &unentered).measured,
        Some(Measured::FunctionNotEntered)
    );
}

#[test]
fn file_not_run_needs_every_file_that_holds_a_site_to_be_unrun() {
    let disk = format!("{ENUM}fn f() -> DiskError {{ DiskError::Full }}\n");
    let other = "fn g() -> super::disk::DiskError { super::disk::DiskError::Full }\n";
    let source = parsed(&tree(&[
        ("storage/mod.rs", "pub mod disk;\npub mod other;\n"),
        (DISK, &disk),
        ("storage/other.rs", other),
    ]));
    let in_disk: Segments = &[(at(&disk, "DiskError::Full", 0), Some(0))];
    let in_other: Segments = &[(at(other, "super::disk::DiskError::Full", 0), Some(0))];
    let functions: &[(&str, Regions, u64)] =
        &[(DISK, &[WHOLE], 0), ("storage/other.rs", &[WHOLE], 0)];
    for (covered, measured) in [
        ([0, 0], Measured::FileNotRun),
        ([0, 2], Measured::FunctionNotEntered),
        ([2, 0], Measured::FunctionNotEntered),
    ] {
        let coverage = raw(
            &[
                (DISK, in_disk, covered[0]),
                ("storage/other.rs", in_other, covered[1]),
            ],
            functions,
        );
        assert_eq!(
            placed(&source, "Full", &coverage).measured,
            Some(measured),
            "{covered:?}"
        );
    }
}

#[test]
fn only_ok_or_gives_its_eager_argument_the_count_of_the_question_mark() {
    for method in [
        "ok_or",
        "unwrap_or",
        "map_or",
        "then_some",
        "or",
        "and",
        "xor",
    ] {
        let body = format!(
            "fn f(x: Option<u8>) -> Result<u8, DiskError> {{ let v = x.{method}(DiskError::Full)?; Ok(v) }}\n"
        );
        let source = parsed(&files(&body));
        let forms: Vec<Form> = source.sites_of(0, "Full").map(|site| site.form).collect();
        assert_eq!(forms, [Form::Eager], "{method}");
        for (own, question) in [(5, 0), (5, 2), (0, 2)] {
            let segments = [("DiskError::Full", 0, Some(own)), ("?;", 0, Some(question))];
            let placement = placed_body(&body, "Full", &segments, 1);
            let expected = match (method, own, question) {
                ("ok_or", _, 0) | (_, 0, _) => (State::Unreached, 0, None),
                ("ok_or", _, question) => (State::Reached, question, None),
                _ => (State::Unplaced, 0, Some(Cause::Unplaceable)),
            };
            assert_eq!(
                (placement.state, placement.count, placement.cause),
                expected,
                "{method} {own} {question}"
            );
        }
    }
}

#[test]
fn only_map_err_gives_its_function_value_the_count_of_the_question_mark() {
    for (body, call) in [
        (
            "fn f(x: Result<u8, u8>) -> Result<u8, DiskError> { let v = x.map_err(DiskError::Gone)?; Ok(v) }\n",
            "map_err",
        ),
        (
            "fn f(x: Result<u8, DiskError>) -> Result<DiskError, DiskError> { let v = x.map(DiskError::Gone)?; Ok(v) }\n",
            "map",
        ),
        (
            "fn f() -> Result<u8, DiskError> { let v = retry(DiskError::Gone)?; Ok(v) }\n",
            "retry",
        ),
    ] {
        assert_eq!(
            parsed(&files(body))
                .sites_of(0, "Gone")
                .next()
                .map(|site| site.form),
            Some(Form::Value),
            "{call}"
        );
        for (own, question) in [(None, 3), (Some(4), 0)] {
            let segments = [("DiskError::Gone", 0, own), ("?;", 0, Some(question))];
            let placement = placed_body(body, "Gone", &segments, 1);
            let expected = match (call, own) {
                ("map_err", _) if question > 0 => (State::Reached, question, None),
                ("map_err", _) => (State::Unreached, 0, None),
                (_, None) => (State::Unplaced, 0, Some(Cause::NoRegion)),
                (_, Some(_)) => (State::Unplaced, 0, Some(Cause::Unplaceable)),
            };
            assert_eq!(
                (placement.state, placement.count, placement.cause),
                expected,
                "{call} {own:?} {question}"
            );
        }
    }
}

#[test]
fn a_site_inside_another_call_in_an_eager_argument_takes_no_chain() {
    let body = "fn f(x: Option<u8>) -> Result<u8, DiskError> { let v = x.ok_or(wrap(DiskError::Full))?; Ok(v) }\n";
    let source = parsed(&files(body));
    let site = source.sites_of(0, "Full").next().expect("one site");
    assert_eq!((site.form, site.chain), (Form::Eager, None));
    let placement = placed_body(
        body,
        "Full",
        &[("DiskError::Full", 0, Some(4)), ("?;", 0, Some(3))],
        1,
    );
    assert_eq!(
        (placement.state, placement.cause),
        (State::Unplaced, Some(Cause::Unplaceable))
    );
}

#[test]
fn a_return_a_leaving_break_and_an_inner_question_mark_take_their_values_out_of_the_argument() {
    let body = "fn f(x: Option<u8>, y: Option<u8>) -> Result<u8, DiskError> { let v = x.ok_or(match y { Some(e) => e, None => return Err(DiskError::Full) })?; Ok(v) }\n\
fn g(x: Option<u8>, c: bool) -> DiskError { loop { let _ = x.ok_or(if c { break DiskError::Full } else { 0 }); } }\n\
fn h(x: Option<u8>, c: bool) -> Result<u8, DiskError> { let v = x.ok_or((if c { Err(DiskError::Full) } else { Ok(0) })?)?; Ok(v) }\n\
fn k(x: Option<u8>) -> Result<u8, DiskError> { let v = x.ok_or('a: { break 'a DiskError::Gone(1) })?; let w = x.ok_or(loop { break DiskError::Gone(2) })?; Ok(v + w) }\n";
    let source = parsed(&files(body));
    let forms: Vec<(&str, Form, bool)> = source
        .sites
        .iter()
        .map(|site| (site.variant.as_str(), site.form, site.chain.is_some()))
        .collect();
    assert_eq!(
        forms,
        [
            ("Full", Form::Path, false),
            ("Full", Form::Path, false),
            ("Full", Form::Path, false),
            ("Gone", Form::Eager, true),
            ("Gone", Form::Eager, true),
        ]
    );
    let segments = [
        ("DiskError::Full", 0, Some(7)),
        ("DiskError::Full", 1, Some(0)),
        ("DiskError::Full", 2, Some(0)),
        ("DiskError::Gone", 0, Some(5)),
        ("DiskError::Gone", 1, Some(5)),
        ("?;", 0, Some(0)),
        ("?)", 0, Some(0)),
        ("?;", 1, Some(0)),
        ("?;", 2, Some(0)),
        ("?;", 3, Some(0)),
    ];
    let full = placed_body(body, "Full", &segments, 1);
    assert_eq!((full.state, full.count), (State::Reached, 7));
    let gone = placed_body(body, "Gone", &segments, 1);
    assert_eq!(
        (gone.state, gone.measured),
        (State::Unreached, Some(Measured::NotConstructed))
    );
}

#[test]
fn a_success_payload_under_a_question_mark_stays_a_comparison() {
    let body = "fn f(e: DiskError) -> Result<bool, ()> { Ok(Ok::<DiskError, ()>(DiskError::Full)? == e) }\n\
fn g(e: DiskError) -> Result<(), ()> { assert_eq!(Ok::<_, ()>(DiskError::Gone(1))?, e, \"{:?}\", DiskError::Torn { at: 0 }); Ok(()) }\n\
fn h(e: DiskError) -> bool { e == if e.ready() { DiskError::Full } else { DiskError::Gone(2) } }\n";
    let source = parsed(&files(body));
    let forms: Vec<(&str, Form)> = source
        .sites
        .iter()
        .map(|site| (site.variant.as_str(), site.form))
        .collect();
    assert_eq!(
        forms,
        [
            ("Full", Form::Compare),
            ("Gone", Form::Compare),
            ("Torn", Form::Struct),
            ("Full", Form::Compare),
            ("Gone", Form::Compare),
        ]
    );
}

#[test]
fn a_closure_passed_to_an_eager_method_takes_the_count_of_its_own_body() {
    let body = "fn f(x: Option<u8>) -> Result<u8, DiskError> { let v = x.map_or(DiskError::Gone(0), |_| DiskError::Full)?; Ok(v) }\n";
    let segments = [
        ("DiskError::Gone", 0, Some(9)),
        ("DiskError::Full", 0, Some(2)),
        ("?;", 0, Some(0)),
    ];
    let full = placed_body(body, "Full", &segments, 1);
    assert_eq!((full.state, full.count), (State::Reached, 2));
    let gone = placed_body(body, "Gone", &segments, 1);
    assert_eq!(
        (gone.state, gone.cause),
        (State::Unplaced, Some(Cause::Unplaceable))
    );
}

#[test]
fn a_comparison_and_an_eager_call_mark_their_own_operands_only() {
    let body = "fn f(e: &DiskError, x: Option<u8>) -> DiskError { let _same = *e == DiskError::Full; let _first = DiskError::Gone(1); assert_ne!(*e, DiskError::Full); let _second = DiskError::Gone(2); let _ = x.ok_or(0); DiskError::Torn { at: 0 } }\n";
    let source = parsed(&files(body));
    let forms: Vec<(&str, Form)> = source
        .sites
        .iter()
        .map(|site| (site.variant.as_str(), site.form))
        .collect();
    assert_eq!(
        forms,
        [
            ("Full", Form::Compare),
            ("Gone", Form::Call),
            ("Full", Form::Compare),
            ("Gone", Form::Call),
            ("Torn", Form::Struct),
        ]
    );
}

#[test]
fn a_test_gated_variant_is_no_variant_and_gets_no_row() {
    let gated = "pub enum DiskError { Full, Gone(u8), #[cfg(test)] Planted, #[cfg(all(test, unix))] Probe(u8), Torn { at: u8 } }\n";
    let source = with_enum(gated);
    let names: Vec<&str> = source.enums[0]
        .variants
        .iter()
        .map(|v| v.name.as_str())
        .collect();
    assert_eq!(names, ["Full", "Gone", "Torn"]);
    let register = measured();
    let synced = sync(&source, "storage", &register);
    assert!(synced.added.is_empty() && synced.removed.is_empty());
    assert_eq!(synced.register, register);
}

#[test]
fn a_site_in_a_test_gated_item_or_statement_is_no_site() {
    for body in [
        "impl DiskError { #[cfg(test)] fn planted() -> Self { DiskError::Full } }\n",
        "trait Probe { #[cfg(test)] fn planted() -> DiskError { DiskError::Full } }\n",
        "#[cfg(test)] impl DiskError { fn planted() -> Self { DiskError::Full } }\n",
        "#[cfg(test)] trait Probe { fn planted() -> DiskError { DiskError::Full } }\n",
        "#[cfg(test)] mod inner { fn planted() -> super::DiskError { super::DiskError::Full } }\n",
        "#[cfg(test)] const FIRST: DiskError = DiskError::Full;\n",
        "#[cfg(test)] static FIRST: DiskError = DiskError::Full;\n",
        "#[test] fn planted() { let _ = DiskError::Full; }\n",
        "#[tokio::test] async fn planted() { let _ = DiskError::Full; }\n",
        "fn f() { #[cfg(test)] let _ = DiskError::Full; }\n",
        "fn f() { #[cfg(test)] check(DiskError::Full); }\n",
        "fn f(v: &mut Vec<DiskError>) { #[cfg(test)] v.push(DiskError::Full); }\n",
        "fn f(c: bool) { #[cfg(test)] if c { check(DiskError::Full); } }\n",
        "fn f(c: bool) { #[cfg(test)] match c { _ => check(DiskError::Full) } }\n",
        "fn f(c: bool) { #[cfg(test)] while c { check(DiskError::Full); } }\n",
        "fn f() { #[cfg(test)] for _ in 0..1 { check(DiskError::Full); } }\n",
        "fn f() { #[cfg(test)] loop { check(DiskError::Full); } }\n",
        "fn f() { #[cfg(test)] unsafe { check(DiskError::Full); } }\n",
        "fn f() -> Result<(), DiskError> { #[cfg(test)] return Err(DiskError::Full); Ok(()) }\n",
        "fn f() { #[cfg(test)] check!(DiskError::Full); }\n",
        "fn f() -> Result<(), DiskError> { #[cfg(test)] check(DiskError::Full)?; Ok(()) }\n",
        "async fn f() { #[cfg(test)] send(DiskError::Full).await; }\n",
    ] {
        let source = parsed(&files(body));
        assert_eq!(owners(&source), [], "{body}");
    }
    let built = "impl DiskError { #[cfg(unix)] fn made() -> Self { DiskError::Full } }\nfn f() { #[cfg(not(test))] check(DiskError::Full); }\n";
    assert_eq!(
        owners(&parsed(&files(built))),
        [
            owner("DiskError::made", "storage::disk::DiskError", "Full"),
            owner("f", "storage::disk::DiskError", "Full"),
        ]
    );
}

#[test]
fn a_macro_body_that_is_no_expression_list_is_read_by_its_paths() {
    let body = "fn f() -> DiskError { pick! { _ = wait() => DiskError::Full, else => { step(Full); DiskError::Gone(1) } } }\n";
    let source = parsed(&files(body));
    assert_eq!(
        owners(&source),
        [
            owner("f", "storage::disk::DiskError", "Full"),
            owner("f", "storage::disk::DiskError", "Gone"),
        ]
    );
}

#[test]
fn a_same_named_enum_resolves_to_the_one_in_the_nearest_directory() {
    let enumeration = "pub enum Refusal { Busy }\n";
    let files = BTreeMap::from([
        ("mod.rs".to_owned(), "pub mod storage;\n".to_owned()),
        (
            "storage/mod.rs".to_owned(),
            "pub mod a;\npub mod b;\n".to_owned(),
        ),
        (
            "storage/a/mod.rs".to_owned(),
            "pub mod table;\npub mod user;\n".to_owned(),
        ),
        ("storage/a/table.rs".to_owned(), enumeration.to_owned()),
        (
            "storage/a/user.rs".to_owned(),
            "use super::table::*;\nfn fa() -> Refusal { Refusal::Busy }\n".to_owned(),
        ),
        ("storage/b.rs".to_owned(), enumeration.to_owned()),
    ]);
    let source = parsed(&files);
    assert_eq!(
        owners(&source),
        [owner("fa", "storage::a::table::Refusal", "Busy")]
    );
    assert!(source.ambiguous.is_empty());
}

#[test]
fn the_register_holds_one_row_a_line_with_keys_in_a_fixed_order() {
    let expected = r#"{
"run": {"commit":"","toolchain":"","flags":"","build":"","worker":"","profiles":[],"roots":"","counts":{},"no_pass":[],"tool":""},
"totals": {"rows":3,"reached":1,"unreached":1,"unplaced":1,"file-not-run":0,"function-not-entered":0,"not-constructed":1},
"live": {"unplaced":1},
"reasons": [
{"id":"not-constructed:storage::disk::DiskError","measured":"not-constructed","sentence":""}
],
"rows": [
{"enum":"storage::disk::DiskError","variant":"Full","sites":[["storage/disk.rs","f","path"]],"state":"reached","count":3},
{"enum":"storage::disk::DiskError","variant":"Gone","sites":[["storage/disk.rs","g","call"]],"state":"unreached","count":0,"measured":"not-constructed","reason":"not-constructed:storage::disk::DiskError"},
{"enum":"storage::disk::DiskError","variant":"Torn","sites":[],"state":"unplaced","cause":"no-site"}
]
}
"#;
    assert_eq!(measured().render(), expected);
    let synced = sync(
        &with_enum("pub enum DiskError { Full, Gone(u8), Lost, Torn { at: u8 } }\n"),
        "storage",
        &measured(),
    );
    let lost =
        r#"{"enum":"storage::disk::DiskError","variant":"Lost","sites":[],"state":"unmeasured"},"#;
    assert_eq!(synced.register.render().lines().nth(10), Some(lost));
}

#[test]
fn measure_counts_each_class_of_unreached_row_under_its_own_name() {
    let text = format!("{ENUM}{BODY}");
    let source = parsed(&files(BODY));
    let zero: Segments = &[
        (at(&text, "DiskError::Full", 0), Some(0)),
        (at(&text, "DiskError::Gone", 0), Some(0)),
    ];
    for (covered, classes) in [(0, (2, 0, 0)), (3, (0, 2, 0))] {
        let coverage = raw(&[(DISK, zero, covered)], &[(DISK, &[WHOLE], 0)]);
        let totals = measure(&source, &coverage, "storage", None, Run::default())
            .expect("the counts sum within u64")
            .totals;
        assert_eq!(
            (
                totals.file_not_run,
                totals.function_not_entered,
                totals.not_constructed
            ),
            classes
        );
        assert_eq!((totals.unreached, totals.unplaced), (2, 1));
    }
}

#[test]
fn the_register_reader_refuses_each_field_its_state_does_not_carry() {
    let synced = sync(
        &with_enum("pub enum DiskError { Full, Gone(u8), Lost, Torn { at: u8 } }\n"),
        "storage",
        &measured(),
    );
    let text = synced.register.render();
    assert!(Register::read(&text).is_ok());
    let reason = r#","reason":"not-constructed:storage::disk::DiskError""#;
    for (from, to) in [
        (
            r#""state":"unmeasured""#,
            r#""state":"unmeasured","count":0"#,
        ),
        (
            r#""state":"unmeasured""#,
            r#""state":"unmeasured","measured":"not-constructed""#,
        ),
        (
            r#""state":"unmeasured""#,
            r#""state":"unmeasured","reason":"not-constructed:storage::disk::DiskError""#,
        ),
        (
            r#""state":"unmeasured""#,
            r#""state":"unmeasured","cause":"no-site""#,
        ),
        (reason, ""),
        (r#""count":0,"measured":"not-constructed""#, r#""count":0"#),
        (
            r#""count":0,"measured":"not-constructed""#,
            r#""measured":"not-constructed""#,
        ),
        (
            r#""measured":"not-constructed","reason""#,
            r#""measured":"never","reason""#,
        ),
        (
            r#""state":"reached","count":3"#,
            r#""state":"reached","count":3,"cause":"no-site""#,
        ),
        (
            r#""state":"unplaced","cause":"no-site""#,
            r#""state":"unplaced","count":0,"cause":"no-site""#,
        ),
        (
            r#""state":"unplaced","cause":"no-site""#,
            r#""state":"unplaced""#,
        ),
        (
            r#""measured":"not-constructed","sentence""#,
            r#""measured":"never","sentence""#,
        ),
    ] {
        let broken = text.replace(from, to);
        assert_ne!(broken, text, "{from}");
        assert!(Register::read(&broken).is_err(), "{from} -> {to}");
    }
}

/// Each line of `gating-cases.txt` is `gated` or `kept` and an attribute.
/// The guard in the workspace suite reads the same file, so the tool and
/// the guard judge one list of attributes.
#[test]
fn each_gating_case_is_listed_exactly_when_it_is_kept() {
    let cases: Vec<(&str, &str)> = include_str!("../gating-cases.txt")
        .lines()
        .map(|line| line.split_once(' ').expect("a verdict and an attribute"))
        .collect();
    let mut disk = String::from(ENUM);
    let mut kept = vec!["storage::disk::DiskError".to_owned()];
    for (index, (verdict, attribute)) in cases.iter().enumerate() {
        disk.push_str(&format!("{attribute}\npub enum Case{index}Error {{ A }}\n"));
        match *verdict {
            "kept" => kept.push(format!("storage::disk::Case{index}Error")),
            "gated" => {}
            other => panic!("{other}: a verdict is `gated` or `kept`"),
        }
    }
    assert!(kept.len() > 1 && kept.len() <= cases.len());
    kept.sort();
    let source = parsed(&tree(&[(DISK, &disk)]));
    let listed: Vec<&str> = source
        .listed("storage")
        .into_iter()
        .map(|index| source.enums[index].path.as_str())
        .collect();
    assert_eq!(listed, kept);
}

#[test]
fn a_measurement_over_a_register_on_disk_keeps_its_reasons_and_names_the_new_run() {
    let mut earlier = measured();
    earlier.reasons[0].id = "not-constructed:by-hand".to_owned();
    earlier.reasons[0].sentence = "written by hand".to_owned();
    earlier.rows[1].reason = Some("not-constructed:by-hand".to_owned());
    earlier.run.commit = "an earlier run".to_owned();
    let checkout = Checkout::new("again", &files(BODY), &earlier);
    let export = checkout.file("export.json", &measured_text());
    let named = Run {
        commit: "this run".to_owned(),
        roots: "1-50".to_owned(),
        ..Run::default()
    };
    let run = checkout.file("run.json", &serde_json::to_string(&named).expect("a run"));
    checkout
        .run(&["measure", "storage", "--export", &export, "--run", &run])
        .expect("measure exits 0");
    let written = Register::read(&checkout.register()).expect("the register reads");
    assert_eq!(written.reasons, earlier.reasons);
    assert_eq!(written.rows, earlier.rows);
    let header = Run {
        tool: crate::digest(),
        ..named
    };
    assert_eq!(written.run, header);
}

#[test]
fn the_tool_digest_is_a_sha_256_in_hex() {
    let digest = crate::digest();
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_ne!(digest, empty);
}

/// The committed registers are the tool's own output for the tree beside
/// them: each renders back byte for byte, `sync` adds and removes no row,
/// and no path names a variant of two enums.
#[test]
fn each_committed_register_is_in_step_with_the_source_beside_it() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let crate_root = root.join("crates/kestrike/src");
    let source = parse(
        &|rel: &str| match std::fs::read_to_string(crate_root.join(rel)) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{rel}: {error}")),
        },
    )
    .expect("the crate parses");
    assert_eq!(source.ambiguous, Vec::<String>::new());
    let mut families = 0;
    for family in crate::source::FAMILIES {
        let path = root.join(format!("verification/reach/{family}.json"));
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && family != "storage" => {
                continue;
            }
            Err(error) => panic!("{}: {error}", path.display()),
        };
        families += 1;
        let register = Register::read(&text).expect("the committed register reads");
        assert_eq!(register.render(), text, "{family}");
        let synced = sync(&source, family, &register);
        assert_eq!(synced.added, Vec::<String>::new(), "{family}");
        assert_eq!(synced.removed, Vec::<String>::new(), "{family}");
        assert_eq!(synced.register, register, "{family}");
    }
    assert!(families > 0);
}

#[test]
fn a_function_span_is_drawn_from_the_code_regions_of_its_own_file() {
    let body = "fn f() -> u8 { 1 }\nfn g() -> DiskError { DiskError::Full }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let site: Segments = &[(at(&text, "DiskError::Full", 0), Some(0))];
    let code = [2, 1, 2, 19, 3, 0, 0, 0];
    let expansion = [1, 1, 999, 1, 3, 0, 1, 1];
    let elsewhere = [1, 1, 999, 1, 3, 1, 0, 0];
    for regions in [vec![code], vec![code, expansion], vec![code, elsewhere]] {
        let coverage = raw(&[(DISK, site, 1)], &[(DISK, &regions, 3)]);
        assert_eq!(
            placed(&source, "Full", &coverage).measured,
            Some(Measured::FunctionNotEntered),
            "{regions:?}"
        );
    }
}

#[test]
fn a_function_value_with_no_question_mark_and_no_region_is_unplaced_for_no_region() {
    let body = "fn f(x: Result<u8, u8>) -> Result<u8, DiskError> { x.map_err(DiskError::Gone) }\n";
    let uncounted = [("DiskError::Gone", 0, None)];
    let entered = placed_body(body, "Gone", &uncounted, 1);
    assert_eq!(
        (entered.state, entered.cause),
        (State::Unplaced, Some(Cause::NoRegion))
    );
    let unentered = placed_body(body, "Gone", &uncounted, 0);
    assert_eq!(
        (unentered.state, unentered.measured),
        (State::Unreached, Some(Measured::FunctionNotEntered))
    );
}

#[test]
fn an_inline_module_sees_the_imports_of_its_file_only_through_a_glob_of_super() {
    let body = "use DiskError::Gone as Made;\n\
mod closed { fn c() { let _ = Made(1); } }\n\
mod open { use super::*; fn d() { let _ = Made(2); } }\n\
fn e() { let _ = Made(3); }\n";
    let source = parsed(&files(body));
    assert_eq!(
        owners(&source),
        [
            owner("d", "storage::disk::DiskError", "Gone"),
            owner("e", "storage::disk::DiskError", "Gone"),
        ]
    );
}

#[test]
fn the_command_line_refuses_a_source_file_or_a_register_it_cannot_read() {
    let mut source = files(BODY);
    source.insert("storage/disk/mod.rs".to_owned(), ENUM.to_owned());
    source.remove(DISK);
    let checkout = Checkout::new("unreadable", &source, &measured());
    let crate_root = checkout.0.join("crates/kestrike/src");
    std::fs::create_dir(crate_root.join(DISK)).expect("a directory in the file's place");
    let refused = checkout
        .run(&["sync", "storage"])
        .expect_err("a directory is no source file");
    assert!(refused.starts_with(DISK), "{refused}");
    std::fs::remove_dir(crate_root.join(DISK)).expect("remove");
    let register = checkout.0.join("verification/reach/storage.json");
    let unreadable = [0xff, 0xfe];
    std::fs::write(&register, unreadable).expect("a register that is no text");
    let export = checkout.file("export.json", &measured_text());
    let run = checkout.file(
        "run.json",
        &serde_json::to_string(&Run::default()).expect("a run"),
    );
    let refused = checkout
        .run(&["measure", "storage", "--export", &export, "--run", &run])
        .expect_err("bytes that are no text are no register");
    assert!(refused.contains("storage.json"), "{refused}");
    assert_eq!(std::fs::read(&register).expect("the register"), unreadable);
}

#[test]
fn construction_counts_that_sum_past_u64_max_are_refused_before_any_write() {
    let body = "fn f() -> DiskError { DiskError::Full }\nfn g() -> DiskError { DiskError::Full }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let sites: Vec<_> = source.sites_of(0, "Full").collect();
    let counts = |first: u64, second: u64| {
        export(
            &[
                (at(&text, "DiskError::Full", 0), Some(first)),
                (at(&text, "DiskError::Full", 1), Some(second)),
            ],
            1,
            1,
        )
    };
    let exact = place(&sites, &counts(u64::MAX - 1, 1)).expect("a sum of u64::MAX");
    assert_eq!((exact.state, exact.count), (State::Reached, u64::MAX));
    let past = counts(u64::MAX, 1);
    let refused = place(&sites, &past).expect_err("a sum past u64::MAX");
    assert!(refused.contains("Full"), "{refused}");
    assert!(measure(&source, &past, "storage", None, Run::default()).is_err());
    let checkout = Checkout::new("overflow", &files(body), &measured());
    let before = checkout.register();
    let export = checkout.file(
        "export.json",
        &export_text(
            &[
                (at(&text, "DiskError::Full", 0), Some(u64::MAX)),
                (at(&text, "DiskError::Full", 1), Some(1)),
            ],
            1,
            1,
        ),
    );
    let run = checkout.file(
        "run.json",
        &serde_json::to_string(&Run::default()).expect("a run"),
    );
    for arguments in [
        &["compare", "storage", "--export", &export][..],
        &["measure", "storage", "--export", &export, "--run", &run],
    ] {
        let refused = checkout.run(arguments).expect_err("a sum past u64::MAX");
        assert!(refused.contains("sum past"), "{arguments:?}: {refused}");
    }
    assert_eq!(checkout.register(), before);
}

#[test]
fn two_conditional_imports_of_one_name_to_two_variants_are_ambiguous() {
    let mut source = files("");
    source.insert(
        DISK.to_owned(),
        "pub enum DiskError { Busy, Full }\n#[cfg(unix)]\nuse DiskError::Busy as V;\n#[cfg(not(unix))]\nuse DiskError::Full as V;\nfn f() -> DiskError { V }\n#[cfg(unix)]\nuse DiskError::Busy as W;\n#[cfg(not(unix))]\nuse self::DiskError::Busy as W;\nfn g() -> DiskError { W }\n".to_owned(),
    );
    let source = parsed(&source);
    assert_eq!(source.ambiguous, ["storage/disk.rs:6: V"]);
    assert_eq!(
        owners(&source),
        [owner("g", "storage::disk::DiskError", "Busy")]
    );
}

#[test]
fn a_raw_self_type_and_raw_item_names_resolve_by_their_plain_names() {
    let source = parsed(&files(
        "impl r#DiskError { fn r#made() -> Self { Self::Full } const r#FIRST: Self = Self::Full; }\nfn r#check(e: &DiskError) -> bool { r#matches!(e, DiskError::Full) }\n",
    ));
    let sites: Vec<(&str, &str, Form)> = source
        .sites
        .iter()
        .map(|site| (site.function.as_str(), site.variant.as_str(), site.form))
        .collect();
    assert_eq!(
        sites,
        [
            ("DiskError::made", "Full", Form::Path),
            ("FIRST", "Full", Form::Table)
        ]
    );
}

#[test]
fn a_function_or_closure_inside_an_initializer_is_code_and_a_block_stays_a_table() {
    let body = "const MAKE: fn() -> DiskError = { fn make() -> DiskError { DiskError::Full } make };\nstatic LATER: fn() -> DiskError = || DiskError::Gone(1);\nconst FIRST: DiskError = { let first = DiskError::Torn { at: 0 }; first };\n";
    let source = parsed(&files(body));
    let forms: Vec<(&str, &str, Form)> = source
        .sites
        .iter()
        .map(|site| (site.function.as_str(), site.variant.as_str(), site.form))
        .collect();
    assert_eq!(
        forms,
        [
            ("make", "Full", Form::Path),
            ("LATER", "Gone", Form::Call),
            ("FIRST", "Torn", Form::Table)
        ]
    );
    let segments = [
        ("DiskError::Full", 0, Some(2)),
        ("DiskError::Gone", 0, Some(3)),
        ("DiskError::Torn", 0, Some(1)),
    ];
    let full = placed_body(body, "Full", &segments, 1);
    assert_eq!((full.state, full.count), (State::Reached, 2));
    let torn = placed_body(body, "Torn", &segments, 1);
    assert_eq!(
        (torn.state, torn.cause),
        (State::Unplaced, Some(Cause::NoSite))
    );
}

#[test]
fn an_enum_or_a_site_in_a_test_gated_arm_field_or_variant_is_skipped() {
    let source = parsed(&files(
        "struct S { e: u8 }\nfn f(x: u8) -> S { match x { #[cfg(test)] 0 => { enum ProbeError { A } let _ = DiskError::Full; } _ => {} } S { #[cfg(test)] e: { enum FieldError { B } 0 }, e: 1 } }\npub enum Code { #[cfg(test)] A = { let _ = DiskError::Full; 1 }, B = 2 }\n",
    ));
    let listed: Vec<&str> = source
        .listed("storage")
        .into_iter()
        .map(|index| source.enums[index].path.as_str())
        .collect();
    assert_eq!(listed, ["storage::disk::DiskError"]);
    assert!(source.sites.is_empty(), "{:?}", source.sites);
}

#[test]
fn the_register_reader_refuses_null_fields_counts_outside_the_state_and_a_reason_of_another_class()
{
    let synced = sync(
        &with_enum("pub enum DiskError { Full, Gone(u8), Lost, Torn { at: u8 } }\n"),
        "storage",
        &measured(),
    );
    let text = synced.register.render();
    assert!(text.contains(r#""variant":"Lost","sites":[],"state":"unmeasured"}"#));
    assert!(Register::read(&text).is_ok());
    let unmeasured = r#""state":"unmeasured""#;
    let reason = r#""reason":"not-constructed:storage::disk::DiskError""#;
    for (from, to) in [
        (unmeasured, r#""state":"unmeasured","count":null"#),
        (unmeasured, r#""state":"unmeasured","measured":null"#),
        (unmeasured, r#""state":"unmeasured","reason":null"#),
        (unmeasured, r#""state":"unmeasured","cause":null"#),
        (
            r#""state":"reached","count":3"#,
            r#""state":"reached","count":0"#,
        ),
        (
            r#""count":0,"measured":"not-constructed""#,
            r#""count":2,"measured":"not-constructed""#,
        ),
        (
            reason,
            r#""reason":"not-constructed:storage::disk::Elsewhere""#,
        ),
        (
            r#""state":"reached","count":3"#,
            r#""state":"reached","count":3,"measured":"not-constructed""#,
        ),
        (
            r#""state":"reached","count":3"#,
            r#""state":"reached","count":3,"reason":"not-constructed:storage::disk::DiskError""#,
        ),
        (
            reason,
            r#""reason":"not-constructed:storage::disk::DiskError","cause":"no-site""#,
        ),
        (
            r#""state":"unplaced","cause":"no-site""#,
            r#""state":"unplaced","measured":"not-constructed","cause":"no-site""#,
        ),
        (
            r#""state":"unplaced","cause":"no-site""#,
            r#""state":"unplaced","reason":"not-constructed:storage::disk::DiskError","cause":"no-site""#,
        ),
        (
            r#"{"id":"not-constructed:storage::disk::DiskError","measured":"not-constructed","sentence":""}"#,
            r#"{"id":"not-constructed:storage::disk::DiskError","measured":"not-constructed","sentence":""},
{"id":"not-constructed:storage::disk::DiskError","measured":"not-constructed","sentence":""}"#,
        ),
        (
            r#""measured":"not-constructed","sentence""#,
            r#""measured":"file-not-run","sentence""#,
        ),
    ] {
        let broken = text.replace(from, to);
        assert_ne!(broken, text, "{from}");
        assert!(Register::read(&broken).is_err(), "{from} -> {to}");
    }
    let checkout = Checkout::new("null", &files(BODY), &measured());
    let path = checkout.0.join("verification/reach/storage.json");
    let nulled = checkout
        .register()
        .replace(r#""cause":"no-site""#, r#""cause":"no-site","count":null"#);
    std::fs::write(&path, &nulled).expect("the register");
    assert!(checkout.run(&["sync", "storage"]).is_err());
    assert_eq!(checkout.register(), nulled);
}

#[test]
fn a_measurement_refuses_an_earlier_reason_row_of_another_class_under_its_id() {
    let mut earlier = measured();
    let gone = earlier
        .rows
        .iter_mut()
        .find(|row| row.variant == "Gone")
        .expect("the Gone row");
    assert_eq!(
        gone.reason.as_deref(),
        Some("not-constructed:storage::disk::DiskError")
    );
    (
        gone.state,
        gone.count,
        gone.measured,
        gone.reason,
        gone.cause,
    ) = (
        "unplaced".to_owned(),
        None,
        None,
        None,
        Some("no-site".to_owned()),
    );
    earlier.reasons[0].measured = "file-not-run".to_owned();
    assert!(Register::read(&earlier.render()).is_ok());
    let coverage = Coverage::read(&measured_text()).expect("the fixture export parses");
    let refused = measure(
        &parsed(&files(BODY)),
        &coverage,
        "storage",
        Some(&earlier),
        Run::default(),
    )
    .expect_err("an id of another class");
    assert!(refused.contains("file-not-run"), "{refused}");
}

#[test]
fn an_uncounted_site_leaves_its_variant_unplaced_only_when_its_own_function_ran() {
    let body = "fn f() -> DiskError { DiskError::Full }\nfn g() -> DiskError { DiskError::Full }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let segments = [
        (at(&text, "DiskError::Full", 0), Some(0)),
        (at(&text, "DiskError::Full", 1), None),
    ];
    for (g, expected) in [
        (0, (State::Unreached, Some(Measured::NotConstructed), None)),
        (2, (State::Unplaced, None, Some(Cause::NoRegion))),
    ] {
        let coverage = custom(
            &[(&segments, 1)],
            &[((2, 1), (2, 99), 1), ((3, 1), (3, 99), g)],
        );
        let placement = placed(&source, "Full", &coverage);
        assert_eq!(
            (placement.state, placement.measured, placement.cause),
            expected,
            "g entered {g} times"
        );
    }
}

#[test]
fn a_gated_import_or_arm_beside_a_live_one_leaves_the_live_one_alone() {
    let mut source = files("");
    source.insert(
        DISK.to_owned(),
        "pub enum DiskError { Busy, Full }\nuse DiskError::Full as V;\n#[cfg(test)]\nuse DiskError::Busy as V;\nfn f() -> DiskError { V }\nfn g(x: u8) -> DiskError { match x { #[cfg(test)] 0 => DiskError::Busy, _ => DiskError::Full } }\n".to_owned(),
    );
    let source = parsed(&source);
    assert_eq!(source.ambiguous, Vec::<String>::new());
    assert_eq!(
        owners(&source),
        [
            owner("f", "storage::disk::DiskError", "Full"),
            owner("g", "storage::disk::DiskError", "Full")
        ]
    );
}

#[test]
fn a_trait_constant_default_is_a_table() {
    let body = "trait Probe { const FIRST: DiskError = DiskError::Full; }\n";
    let source = parsed(&files(body));
    let sites: Vec<(&str, Form)> = source
        .sites
        .iter()
        .map(|site| (site.function.as_str(), site.form))
        .collect();
    assert_eq!(sites, [("FIRST", Form::Table)]);
    let placement = placed_body(body, "Full", &[("DiskError::Full", 0, Some(5))], 1);
    assert_eq!(
        (placement.state, placement.cause),
        (State::Unplaced, Some(Cause::NoSite))
    );
}

#[test]
fn a_remeasurement_refreshes_the_functions_of_a_kept_reason_and_keeps_its_sentence() {
    let body =
        "fn g() -> DiskError { DiskError::Full }\nfn f() -> DiskError { DiskError::Gone(1) }\n";
    let text = format!("{ENUM}{body}");
    let source = parsed(&files(body));
    let coverage = custom(
        &[(
            &[
                (at(&text, "DiskError::Full", 0), Some(0)),
                (at(&text, "DiskError::Gone", 0), Some(0)),
            ],
            1,
        )],
        &[((1, 1), (1, 99), 1), ((2, 1), (3, 99), 0)],
    );
    let mut earlier = measure(&source, &coverage, "storage", None, Run::default())
        .expect("the counts sum within u64");
    assert_eq!(earlier.reasons.len(), 1);
    let id = earlier.reasons[0].id.clone();
    earlier.reasons[0]
        .functions
        .push((DISK.to_owned(), "stale".to_owned()));
    earlier.reasons[0].sentence = "Written by hand.".to_owned();
    let again = measure(
        &source,
        &coverage,
        "storage",
        Some(&earlier),
        Run::default(),
    )
    .expect("the counts sum within u64");
    assert_eq!(again.reasons.len(), 1);
    let reason = &again.reasons[0];
    assert_eq!(
        (reason.id.as_str(), reason.sentence.as_str()),
        (id.as_str(), "Written by hand.")
    );
    let functions: Vec<&str> = reason.functions.iter().map(|(_, f)| f.as_str()).collect();
    assert_eq!(functions, ["f", "g"]);
}
