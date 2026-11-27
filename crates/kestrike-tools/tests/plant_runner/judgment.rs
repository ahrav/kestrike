//! The judgment of a swept plant, row by row: each row's sweep status, last exit, `suspects.jsonl`,
//! manifests and children's output go through `plants::judge`, whose entry must equal the row's entry
//! member for member and in order. The stand-in children return the exit and output of `campaign confirm`
//! and each seed check, and write `confirm.err` where the judgment reads it.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use kestrike_tools::json::MAX_INTEGER_DIGITS;
use kestrike_tools::json::{self, Value};
use kestrike_tools::plants::{
    Ask, Entry, Finished, Manifest, NoVerdict, Options, Outcome, Pins, Plant, Suspect, Sweep,
    archive_pins, first_object, judge,
};
use kestrike_tools::text::Text;

use super::judgment_rows::{ROWS, WITH_OPTIONS};
use super::repository::{Repository, chmod, is_root, private_dir, write};

/// The exit of a child that did not run: its output is the reason the caller gives.
pub const REFUSED: i32 = i32::MIN;

/// The state of a row's `suspects.jsonl`.
pub enum List {
    Missing,
    File(&'static [u8]),
    /// A link to a regular file of these bytes.
    Link(&'static [u8]),
    Directory,
    Dangling,
}

/// One row: the inputs, and the entry, the calls of `confirm` and the seed checks they give.
pub struct Row {
    pub name: &'static str,
    pub status: &'static str,
    pub code: i32,
    pub list: List,
    pub manifests: &'static [&'static str],
    /// The exit, output and error output of `campaign confirm`.
    pub confirm: (i32, &'static str, &'static [u8]),
    /// The exit and output of each seed check's `campaign sim run`, in call order.
    pub seeds: &'static [(i32, &'static str)],
    pub confirms: usize,
    /// Each seed check that ran: `PROFILE/RUN-SEED` and the manifest it ran.
    pub asked: &'static [(&'static str, &'static str)],
    pub entry: &'static str,
}

/// `manifest_of` is the manifest a sweep wrote for `profile` in every row.
pub fn manifest_of(profile: &str) -> String {
    format!(
        "profile = {profile}\nroot = 0\nbuild = x\nexecutable = x\nplatform = x\ntoolchain = x\nruns = 1\n"
    )
}

/// What `campaign confirm` leaves of its error output.
#[derive(Clone, Copy)]
enum Errors {
    Written,
    Missing,
    Unreadable,
}

/// The children of a row: `campaign confirm`, which writes the row's error output where the judgment
/// reads it, and each seed check, which pins the manifest it is given and takes the next seed output.
struct Children {
    row: &'static Row,
    errors: Errors,
    place: std::path::PathBuf,
    work: String,
    pins: Pins,
    confirms: usize,
    asked: Vec<(String, String)>,
}

impl Ask for Children {
    fn confirm(&mut self) -> Result<(i32, String), NoVerdict> {
        self.confirms += 1;
        let (code, out, err) = self.row.confirm;
        if code == REFUSED {
            return Err(NoVerdict::plain(out));
        }
        let errors = self.place.join("confirm.err");
        match self.errors {
            Errors::Written => write(&errors, err),
            Errors::Missing => {}
            Errors::Unreadable => {
                write(&errors, err);
                chmod(&errors, 0o000);
            }
        }
        Ok((code, out.to_owned()))
    }

    fn run_seed(&mut self, suspect: &Suspect, manifest: &Manifest) -> Result<(i32, String), Text> {
        let pinned = manifest.pinned(&self.pins);
        let place = format!("{}/{}-{}", suspect.profile(), suspect.run(), suspect.seed());
        self.asked
            .push((place, pinned.to_str().expect("UTF-8").to_owned()));
        let (code, out) = self.row.seeds[self.asked.len() - 1];
        if code == REFUSED {
            return Err(Text::from(out));
        }
        Ok((code, out.replace("{WORK}", &self.work)))
    }
}

/// `pins` are the pins an archive whose build digest is `build` prints.
pub fn pins(build: &str) -> Pins {
    let printed = format!(
        r#"{{"build": "{build}", "executable": "e{n}", "platform": "p{n}", "toolchain": "t{n}"}}"#,
        n = &build[1..]
    );
    archive_pins(0, &printed, "an archive", Path::new("archive.err")).expect("pins")
}

/// `alpha` is the fixture's plant `alpha`, which expects `smoke` and then `crash-loop`, with the run's
/// default options: a floor of 300 runs and 10 sweeps.
pub fn alpha(repository: &Repository) -> (Plant, Options) {
    alpha_with(repository, &[])
}

/// `alpha_with` is the fixture's plant `alpha` with the options `args` give.
fn alpha_with(repository: &Repository, args: &[&str]) -> (Plant, Options) {
    let args: Vec<&str> = ["--plant", "alpha"].iter().chain(args).copied().collect();
    let Outcome::Run(inputs) = repository.prepare(&repository.call(&args)) else {
        panic!("the fixture's checks pass");
    };
    (inputs.plants()[0].clone(), inputs.options().clone())
}

/// `row` is the row named `name`.
pub fn row(name: &str) -> &'static Row {
    ROWS.iter()
        .find(|row| row.name == name)
        .expect("a row of that name")
}

/// `judged` judges `plant` on `row` in the work directory `work` and returns its finished entry with the
/// children's record of what they were asked.
fn judged(row: &'static Row, plant: &(Plant, Options), work: &Path) -> (Finished, Children) {
    judged_with(row, plant, work, Errors::Written)
}

fn judged_with(
    row: &'static Row,
    (plant, options): &(Plant, Options),
    work: &Path,
    errors: Errors,
) -> (Finished, Children) {
    let place = work.join(format!("plants/{}", plant.id()));
    let root = place.join("root");
    private_dir(&root.join("manifests"));
    for profile in row.manifests {
        write(
            &root.join(format!("manifests/{profile}.manifest")),
            manifest_of(profile),
        );
    }
    let list = root.join("suspects.jsonl");
    match row.list {
        List::Missing => {}
        List::File(bytes) => write(&list, bytes),
        List::Link(bytes) => {
            write(&root.join("listed.jsonl"), bytes);
            symlink(root.join("listed.jsonl"), &list).expect("linked");
        }
        List::Directory => private_dir(&list),
        List::Dangling => symlink(root.join("absent"), &list).expect("linked"),
    }
    let status = row
        .status
        .replace("{NINES}", &"9".repeat(MAX_INTEGER_DIGITS));
    let status = first_object(&status, "sweep-status").expect("the row's status is an object");
    let mut entry = Entry::new(plant);
    entry.set_commit(&Text::from("c0mmit"));
    entry.set_tree(&Text::from("tr33"));
    assert!(entry.archived(&pins("a1")), "the plant expects a profile");
    let mut children = Children {
        row,
        errors,
        place: place.clone(),
        work: work.to_str().expect("a UTF-8 work directory").to_owned(),
        pins: pins("b0"),
        confirms: 0,
        asked: Vec::new(),
    };
    let sweep = Sweep::new(row.code, &status, &place, work, options).expect("an exit of 0 or 1");
    judge(&mut entry, &sweep, &mut children);
    let entry = entry.finish(work).expect("a judged entry holds its result");
    (entry, children)
}

/// `judged_row` is the finished entry of `plant` on the row named `name`.
pub fn judged_row(name: &str, plant: &(Plant, Options), work: &Path) -> Finished {
    judged(row(name), plant, work).0
}

/// `shown` is the entry's members as compact JSON.
pub fn shown(entry: &Finished) -> String {
    json::text(&Value::Object(entry.members().clone()))
}

/// `checks` judges each row on `plant` and compares its entry, its count of `confirm` calls and each seed
/// check it asks, with the manifest that check runs.
fn checks(
    repository: &Repository,
    plant: &(Plant, Options),
    rows: impl IntoIterator<Item = &'static Row>,
) {
    for (number, row) in rows.into_iter().enumerate() {
        let work = repository.scratch.join(format!("work-{number}"));
        let (entry, children) = judged(row, plant, &work);
        let expected = row
            .entry
            .replace("{WORK}", work.to_str().expect("a UTF-8 work directory"));
        assert_eq!(shown(&entry), expected, "{}", row.name);
        assert_eq!(children.confirms, row.confirms, "{}: confirms", row.name);
        let asked: Vec<(&str, &str)> = children
            .asked
            .iter()
            .map(|(place, text)| (place.as_str(), text.as_str()))
            .collect();
        assert_eq!(asked, row.asked, "{}: seed checks", row.name);
        fs::remove_dir_all(&work).expect("removed");
    }
}

/// Every row gives its entry, its count of `confirm` calls and each seed check it asks, with the manifest
/// that check runs.
#[test]
fn each_row_gives_its_entry_and_asks_its_children() {
    let repository = Repository::new();
    checks(&repository, &alpha(&repository), ROWS);
}

/// The run's `--runs` and `--rounds` decide the floor each profile's `next` must reach and the sweeps the
/// reason names.
#[test]
fn the_runs_options_set_the_floor_and_the_sweeps_of_a_judgment() {
    for (args, row) in WITH_OPTIONS {
        let repository = Repository::new();
        checks(&repository, &alpha_with(&repository, args), [row]);
    }
    if WITH_OPTIONS.is_empty() {
        panic!("rows under other options");
    }
}

/// A sweep that exits otherwise than 0 or 1 has no judgment.
#[test]
fn a_sweep_judged_exits_0_or_1() {
    let repository = Repository::new();
    let (_, options) = alpha(&repository);
    let status = first_object("{}", "sweep-status").expect("an object");
    let place = Path::new("plants/alpha");
    for (code, judged) in [(0, true), (1, true), (2, false), (-9, false), (4, false)] {
        let sweep = Sweep::new(code, &status, place, Path::new("/w"), &options);
        assert_eq!(sweep.is_some(), judged, "{code}");
    }
}

/// At an exit 4, an error output of `confirm` that cannot be read fails the run, named from the work
/// directory; at an exit 0 it is not read.
#[test]
fn an_unreadable_confirm_error_output_fails_the_run_at_an_exit_4_alone() {
    let repository = Repository::new();
    let plant = alpha(&repository);
    let held = row("a_confirm_held_at_its_backlog_keeps_its_findings");
    let caught = row("a_confirmed_suspect_whose_seed_passes_on_the_head_is_caught");
    let mut cases = vec![
        (held, Errors::Missing, Some("No such file or directory")),
        (caught, Errors::Missing, None),
    ];
    if !is_root() {
        cases.push((held, Errors::Unreadable, Some("Permission denied")));
    }
    for (number, (row, errors, failed)) in cases.into_iter().enumerate() {
        let work = repository.scratch.join(format!("errors-{number}"));
        let (entry, _) = judged_with(row, &plant, &work, errors);
        let reason = entry.reason().to_string();
        match failed {
            Some(error) => assert_eq!(
                reason,
                format!("the run failed: {error} (plants/alpha/confirm.err)")
            ),
            None => assert_eq!(reason, "violation: a in run 1 of smoke"),
        }
        let errors = work.join("plants/alpha/confirm.err");
        if errors.exists() {
            chmod(&errors, 0o600);
        }
        fs::remove_dir_all(&work).expect("removed");
    }
}

/// A `suspects.jsonl` that cannot be opened fails the run, named from the work directory, and asks no
/// child.
#[test]
fn an_unreadable_suspect_list_fails_the_run() {
    if is_root() {
        return;
    }
    let repository = Repository::new();
    let plant = alpha(&repository);
    let work = repository.scratch.join("unreadable-list");
    let caught = row("a_confirmed_suspect_whose_seed_passes_on_the_head_is_caught");
    let list = work.join("plants/alpha/root/suspects.jsonl");
    let place = work.join("plants/alpha");
    private_dir(&place.join("root/manifests"));
    let List::File(bytes) = caught.list else {
        panic!("the row lists its suspects");
    };
    write(&list, bytes);
    chmod(&list, 0o000);
    let status = first_object(caught.status, "sweep-status").expect("an object");
    let mut entry = Entry::new(&plant.0);
    assert!(entry.archived(&pins("a1")));
    let mut children = Children {
        row: caught,
        errors: Errors::Written,
        place: place.clone(),
        work: String::new(),
        pins: pins("b0"),
        confirms: 0,
        asked: Vec::new(),
    };
    let sweep = Sweep::new(0, &status, &place, &work, &plant.1).expect("an exit of 0");
    judge(&mut entry, &sweep, &mut children);
    let entry = entry.finish(&work).expect("a result");
    assert_eq!(
        entry.reason().to_string(),
        "the run failed: Permission denied (plants/alpha/root/suspects.jsonl)"
    );
    assert_eq!((children.confirms, children.asked.len()), (0, 0));
    chmod(&list, 0o600);
    fs::remove_dir_all(&work).expect("removed");
}
