use std::cell::RefCell;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use kestrike_tools::gameday::{Evidence, FILE_LIMIT, ReadError, ends_observation, read_evidence};
use kestrike_tools::host_stop_controller::{Command, entry};
use kestrike_tools::json::{Value, indented_in_order};

use super::restoring::dumps;
use super::steps::Step;
use super::stop_run::{seconds, time};
use super::{Case, listing, member};
use crate::host_stop_support::{bounds, object, tree, value};

pub(crate) fn held() -> PathBuf {
    tree().join("scripts/gameday-fixtures/held")
}

/// `indented_one` writes Python's `json.dumps(value, indent=1)` and a newline, with members in
/// document order.
pub(crate) fn indented_one(value: &Value) -> String {
    let mut out = String::new();
    for line in indented_in_order(value).split('\n') {
        let spaces = line.len() - line.trim_start_matches(' ').len();
        out.push_str(&" ".repeat(spaces / 2));
        out.push_str(&line[spaces..]);
        out.push('\n');
    }
    out
}

pub(crate) fn parse(path: &Path) -> Value {
    value(&fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())))
}

/// `copy_tree` creates `to` and each directory with mode 0700 and copies each file of `from`,
/// skipping each entry `skip` names and its descendants.
pub(crate) fn copy_tree(from: &Path, to: &Path, skip: &[&str]) {
    DirBuilder::new()
        .mode(0o700)
        .create(to)
        .expect("the copy's root is made");
    for relative in listing(from) {
        let skipped = skip
            .iter()
            .any(|name| relative == *name || relative.starts_with(&format!("{name}/")));
        if skipped {
            continue;
        }
        let (source, target) = (from.join(&relative), to.join(&relative));
        if fs::symlink_metadata(&source).is_ok_and(|found| found.is_dir()) {
            DirBuilder::new()
                .mode(0o700)
                .create(&target)
                .expect("a directory is copied");
        } else {
            fs::copy(&source, &target).expect("a file is copied");
        }
    }
}

/// `window_end` returns the held package's run end and `clock_error_seconds`.
pub(crate) fn window_end() -> (f64, f64) {
    let p = parse(&held().join("package.json"));
    let end = seconds(member(member(&p, "run"), "end"));
    (end, seconds(member(&p, "clock_error_seconds")))
}

/// `judged` returns `Err` with the refusal message for `ReadError::Refused` and panics on other
/// read errors.
pub(crate) fn judged(root: &Path) -> Result<Evidence, String> {
    read_evidence(root, FILE_LIMIT, &bounds()).map_err(|error| match error {
        ReadError::Refused(refusal) => refusal.message().to_string(),
        other => panic!("{other:?} is a refusal"),
    })
}

pub(crate) fn ends(evidence: &Evidence) -> bool {
    let at = evidence
        .file("injection/restoration.json")
        .map(|restoration| member(restoration, "time").clone());
    ends_observation(evidence.package(), at.as_ref())
}

pub(crate) fn marks_in(root: &Path) -> Vec<String> {
    listing(&root.join("injection"))
}

pub(crate) fn standing_marks(root: &Path) -> Vec<String> {
    marks_in(root)
        .into_iter()
        .filter(|name| name != "collected.json")
        .map(|name| format!("injection/{name}"))
        .collect()
}

/// The path the descriptor `fd` of this process names, or an empty path once it is closed.
pub(crate) fn named_fd(fd: i32) -> PathBuf {
    fs::read_link(format!("/proc/self/fd/{fd}")).unwrap_or_default()
}

/// Whether `step` syncs the file or the directory at `path`.
pub(crate) fn syncs_at(step: &Step<'_>, path: &Path) -> bool {
    match step {
        Step::Fsync(fd) => named_fd(*fd) == path,
        Step::FsyncDirectory(synced) => synced == path,
        _ => false,
    }
}

impl Case {
    /// Moves the plane's clock forward to `at`; a clock at or past `at` stays.
    pub(crate) fn advance_to(&self, at: f64) {
        let mut plane = self.plane.borrow_mut();
        plane.t = plane.t.max(at);
    }

    /// A copy of the held fixture without its `injection/`, which holds this case's marks in its
    /// place. `records` updates the first row of each named shard's record file and `versions`
    /// adds rows to it, sorted by time, and `coverage.json` counts the rows each file then holds.
    pub(crate) fn copy(
        &self,
        records: &[(&str, Value)],
        versions: &[(&str, Vec<Value>)],
    ) -> PathBuf {
        let root = self.scratch.0.join("judged");
        copy_tree(&held(), &root, &["injection"]);
        copy_tree(
            &self.evidence.join("injection"),
            &root.join("injection"),
            &[],
        );
        let mut shards: Vec<&str> = records.iter().map(|(shard, _)| *shard).collect();
        shards.extend(versions.iter().map(|(shard, _)| *shard));
        shards.sort_unstable();
        shards.dedup();
        for shard in shards {
            let path = root.join(format!("records/{shard}.jsonl"));
            let text = fs::read_to_string(&path).expect("a record file reads");
            let mut rows: Vec<Value> = text.lines().map(value).collect();
            for (_, change) in records.iter().filter(|(named, _)| *named == shard) {
                let Value::Object(first) = &mut rows[0] else {
                    panic!("a record row is an object")
                };
                for (key, member) in object(change.clone()).iter() {
                    first.insert(key.clone(), member.clone());
                }
            }
            for (_, added) in versions.iter().filter(|(named, _)| *named == shard) {
                rows.extend(added.iter().cloned());
            }
            rows.sort_by(|a, b| time(a).total_cmp(&time(b)));
            let lines: String = rows.iter().map(|row| format!("{}\n", dumps(row))).collect();
            fs::write(&path, lines).expect("a record file is written");
            let mut coverage = parse(&root.join("coverage.json"));
            let count = value(&rows.len().to_string());
            let key = format!("records/{shard}.jsonl");
            super::set(&mut coverage, &[key.as_str(), "lines"], count);
            fs::write(root.join("coverage.json"), indented_one(&coverage)).expect("written");
        }
        root
    }

    /// Runs `seal` over `root` and returns its exit code.
    pub(crate) fn seal_at(&mut self, root: &Path) -> u8 {
        let command = Command::Seal {
            operator: self.write_operator(),
            evidence: root.as_os_str().to_owned(),
        };
        self.in_context(|cx| entry(&command, cx))
    }

    /// Runs `restore` over `root` with no reviewed record and returns its exit code.
    pub(crate) fn restore_at(&mut self, root: &Path) -> u8 {
        self.plane.borrow_mut().deadline = None;
        let command = Command::Restore {
            operator: self.write_operator(),
            evidence: root.as_os_str().to_owned(),
            reviewed: None,
        };
        self.in_context(|cx| entry(&command, cx))
    }
}

impl Case {
    /// Seals the copy at `root` once the run window has ended, keeps it under `name` and returns
    /// the judge's load of it, which admits the sealed copy.
    pub(crate) fn judge_copy(&mut self, root: &Path, name: &str) -> Evidence {
        self.advance_to(window_end().0 + 30.0);
        assert_eq!(self.seal_at(root), 0, "{}", self.output());
        self.keep_tree(root, name);
        judged(root).unwrap_or_else(|reason| panic!("{reason}\n{}", self.output()))
    }

    /// [`Case::judge_copy`] over a copy that holds the held fixture's collections unchanged.
    pub(crate) fn judge(&mut self, name: &str) -> (PathBuf, Evidence) {
        let root = self.copy(&[], &[]);
        let evidence = self.judge_copy(&root, name);
        (root, evidence)
    }

    /// Starts the target once the run window has ended and restores it, so the restoration ends no
    /// observation.
    pub(crate) fn restore_after_the_run_window(&mut self, initializing: usize) {
        let end = window_end().0;
        self.advance_to(end + 20.0);
        self.start_target(initializing);
        assert_eq!(self.restore(None), 0, "{}", self.output());
        assert!(
            time(&self.marks()["restoration"]) > end,
            "{:?}",
            self.marks()
        );
    }

    /// An unsealed copy of a clean run restored after the run window.
    pub(crate) fn restored_copy(&mut self) -> PathBuf {
        assert_eq!(self.run(), 0, "{}", self.output());
        self.restore_after_the_run_window(0);
        self.copy(&[], &[])
    }

    /// A seal of `root` exits 2 and prints `reason`, with no call made and the marks of
    /// `root/injection` as they stood.
    pub(crate) fn assert_seal_refused(&mut self, root: &Path, reason: &str) {
        let (calls, before, seen) = (self.log().len(), marks_in(root), self.output().len());
        assert_eq!(self.seal_at(root), 2, "{}", self.output());
        let output = self.output();
        assert!(
            output[seen..].contains(reason),
            "{reason:?} in {}",
            &output[seen..]
        );
        assert_eq!(
            (self.log().len(), marks_in(root)),
            (calls, before),
            "{output}"
        );
    }

    /// The relative path of each file under `root` whose sync a file step makes, in order, shared
    /// with the plant that records them.
    pub(crate) fn reads_under(&self, root: &Path) -> Rc<RefCell<Vec<String>>> {
        let read = Rc::new(RefCell::new(Vec::new()));
        let (seen, root) = (Rc::clone(&read), root.to_path_buf());
        self.plant(Box::new(move |_, step| {
            if let Step::Fsync(fd) = step
                && let Ok(rel) = named_fd(*fd).strip_prefix(&root)
                && !rel.to_string_lossy().ends_with("(deleted)")
            {
                seen.borrow_mut().push(rel.to_string_lossy().into_owned());
            }
            None
        }));
        read
    }
}
