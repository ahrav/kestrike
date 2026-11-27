//! The judgment of a swept plant, row by row: each row's sweep status, last exit, `suspects.jsonl`,
//! manifests and children's output go through `plants::judge`, whose entry must equal the row's entry
//! member for member and in order. The stand-in children return the exit and output of `campaign confirm`
//! and each seed check, and write `confirm.err` where the judgment reads it.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use kestrike_tools::json::{self, Value};
use kestrike_tools::plants::{
    Ask, Entry, Manifest, NoVerdict, Options, Outcome, Pins, Plant, Suspect, Sweep, archive_pins,
    first_object, judge,
};
use kestrike_tools::text::Text;

use super::judgment_rows::ROWS;
use super::repository::{Repository, chmod, is_root, private_dir, write};

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
    pins: Pins,
    confirms: usize,
    asked: Vec<(String, String)>,
}

impl Ask for Children {
    fn confirm(&mut self) -> Result<(i32, String), NoVerdict> {
        self.confirms += 1;
        let (code, out, err) = self.row.confirm;
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
        let pinned = manifest.pinned(&self.pins, suspect.seed());
        let place = format!("{}/{}-{}", suspect.profile(), suspect.run(), suspect.seed());
        self.asked
            .push((place, pinned.to_str().expect("UTF-8").to_owned()));
        let (code, out) = self.row.seeds[self.asked.len() - 1];
        Ok((code, out.to_owned()))
    }
}

fn base_pins() -> Pins {
    let printed = r#"{"build": "b0", "executable": "e0", "platform": "p0", "toolchain": "t0"}"#;
    archive_pins(
        0,
        printed,
        "the unpatched head",
        Path::new("base/archive.err"),
    )
    .expect("pins")
}

/// `alpha` is the fixture's plant `alpha`, which expects `smoke` and then `crash-loop`, with the run's
/// default options: a floor of 300 runs and 10 sweeps.
pub fn alpha(repository: &Repository) -> (Plant, Options) {
    let Outcome::Run(inputs) = repository.prepare(&repository.call(&["--plant", "alpha"])) else {
        panic!("the fixture's checks pass");
    };
    (inputs.plants()[0].clone(), inputs.options().clone())
}

/// `judged` judges `plant` on `row` in the work directory `work` and returns its finished entry with the
/// children's record of what they were asked.
fn judged(row: &'static Row, plant: &(Plant, Options), work: &Path) -> (Entry, Children) {
    judged_with(row, plant, work, Errors::Written)
}

fn judged_with(
    row: &'static Row,
    (plant, options): &(Plant, Options),
    work: &Path,
    errors: Errors,
) -> (Entry, Children) {
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
    let status = first_object(row.status, "sweep-status").expect("the row's status is an object");
    let mut entry = Entry::new(plant);
    entry.set_commit(&Text::from("c0mmit"));
    entry.set_tree(&Text::from("tr33"));
    entry.set_archive(&Text::from("a1"));
    let mut children = Children {
        row,
        errors,
        place: place.clone(),
        pins: base_pins(),
        confirms: 0,
        asked: Vec::new(),
    };
    let sweep = Sweep::new(row.code, &status, &place, work, options).expect("an exit of 0 or 1");
    judge(&mut entry, &sweep, &mut children);
    entry.finish(work);
    (entry, children)
}

/// `judged_row` is the finished entry of `plant` on the row named `name`.
pub fn judged_row(name: &str, plant: &(Plant, Options), work: &Path) -> Entry {
    let row = ROWS
        .iter()
        .find(|row| row.name == name)
        .expect("a row of that name");
    let (entry, _) = judged(row, plant, work);
    entry
}

fn shown(entry: &Entry) -> String {
    json::text(&Value::Object(entry.members().clone()))
}

/// Every row gives its entry, its count of `confirm` calls and each seed check it asks, with the manifest
/// that check runs.
#[test]
fn each_row_gives_its_entry_and_asks_its_children() {
    let repository = Repository::new();
    let plant = alpha(&repository);
    for (number, row) in ROWS.iter().enumerate() {
        let work = repository.scratch.join(format!("work-{number}"));
        let (entry, children) = judged(row, &plant, &work);
        assert_eq!(shown(&entry), row.entry, "{}", row.name);
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
    let held = ROWS
        .iter()
        .find(|row| row.name == "a_confirm_held_at_its_backlog_keeps_its_findings")
        .expect("a row");
    let caught = ROWS
        .iter()
        .find(|row| row.name == "a_confirmed_suspect_whose_seed_passes_on_the_head_is_caught")
        .expect("a row");
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
        let reason = entry.reason().expect("a reason").to_string();
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
