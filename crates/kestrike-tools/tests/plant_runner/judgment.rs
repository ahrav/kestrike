//! The judgment of a swept plant, row by row: each row's sweep status, last exit, `suspects.jsonl`,
//! manifests and children's output go through `plants::judge`, whose entry must equal the row's entry
//! member for member and in order. The stand-in children read what `campaign confirm` and each seed check
//! printed with the library's own readers, as a run does.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use kestrike_tools::json::{self, Integer, Value};
use kestrike_tools::plants::seed::{SeedCheck, ending, manifest};
use kestrike_tools::plants::{
    Ask, Confirmed, Entry, NoVerdict, Pins, Plant, Suspect, Sweep, archive_pins, confirmed,
    first_object, judge,
};
use kestrike_tools::text::Text;

use super::judgment_rows::ROWS;
use super::repository::{Repository, private_dir, write};

/// The state of a row's `suspects.jsonl`.
pub enum List {
    Missing,
    File(&'static [u8]),
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

/// The children of a row: `campaign confirm` and each seed check, which reads the sweep's manifest and
/// runs nothing when its digest differs, and otherwise takes the next seed output.
struct Children<'a> {
    row: &'a Row,
    root: PathBuf,
    work: PathBuf,
    pins: Pins,
    confirms: usize,
    asked: Vec<(String, String)>,
}

impl Ask for Children<'_> {
    fn confirm(&mut self) -> Result<Confirmed, NoVerdict> {
        self.confirms += 1;
        let (code, out, err) = self.row.confirm;
        let errors = self.work.join("plants/alpha/confirm.err");
        write(&errors, err);
        confirmed(code, out, &errors, &self.work)
    }

    fn seed(&mut self, suspect: &Suspect, digest: Option<&Value>) -> SeedCheck {
        let manifest = match manifest(&self.root, suspect, digest) {
            Ok(manifest) => manifest,
            Err(check) => return check,
        };
        let pinned = manifest.pinned(&self.pins, suspect.seed());
        let place = format!("{}/{}-{}", suspect.profile(), suspect.run(), suspect.seed());
        self.asked
            .push((place, pinned.to_str().expect("UTF-8").to_owned()));
        let (code, out) = self.row.seeds[self.asked.len() - 1];
        ending(code, out)
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

/// `alpha` is the fixture's plant `alpha`, which expects `smoke` and then `crash-loop`.
fn alpha(repository: &Repository) -> Plant {
    let kestrike_tools::plants::Outcome::Run(inputs) =
        repository.prepare(&repository.call(&["--plant", "alpha"]))
    else {
        panic!("the fixture's checks pass");
    };
    inputs.plants()[0].clone()
}

fn judged(row: &'static Row, plant: &Plant, work: &Path) -> (Entry, Children<'static>) {
    let root = work.join("plants/alpha/root");
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
        root: root.clone(),
        work: work.to_path_buf(),
        pins: base_pins(),
        confirms: 0,
        asked: Vec::new(),
    };
    let (floor, rounds) = (Integer::from(300u64), Integer::from(10u64));
    let sweep = Sweep::new(row.code, &status, &root, work, &floor, &rounds);
    judge(&mut entry, &sweep, &mut children);
    entry.finish(work);
    (entry, children)
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
