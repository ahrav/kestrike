//! Tests of the watermark file log's in-place raises against a rename over its path.

use super::watermark::Watermark;
use super::{FileLog, Key, Version, WatermarkLog};
use crate::net::ownership::Shard;
/// A record keeps the handle of the file it wrote for in-place raises, so a raise writes that file whatever file
/// the path names afterwards, and refuses `NotFound` once the path names another: a later load of the path reads
/// none of the raise. Here another writer renames its file over the path during the record, at the record's
/// directory open, after the record's own rename. The sibling renames after the record returns. Each raise refuses
/// `NotFound` with the other file intact; the control renames nothing, and the raise is loaded.
#[test]
fn a_rename_over_the_path_during_the_record_keeps_the_raise_out_of_the_other_file() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::bind::record_step::{RecordStep, SCRIPT, Script};

    let directory = std::env::temp_dir().join(format!("watermark-reopen-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let (path, other) = (directory.join("mark"), directory.join("other"));
    let ours_key = Key::Page(Shard::new(1).unwrap(), 0);
    let theirs_key = Key::Page(Shard::new(2).unwrap(), 0);
    let marked = |key, version| {
        let mut mark = Watermark::default();
        assert_eq!(
            mark.observe(key, (Version::new(version).unwrap(), (7, 7))),
            Ok(true)
        );
        mark
    };
    let (ours, theirs) = (marked(ours_key, 1), marked(theirs_key, 5));
    let raised = marked(ours_key, 2);
    let load = || {
        FileLog::new(path.clone())
            .unwrap()
            .load()
            .map_err(|error| error.kind())
    };
    let mut seen = Vec::new();
    for case in ["during record", "after record", "control"] {
        std::fs::remove_file(&path).ok();
        FileLog::new(other.clone())
            .unwrap()
            .record(&theirs)
            .unwrap();
        let renamed = Rc::new(Cell::new(false));
        let (flag, from, to) = (Rc::clone(&renamed), other.clone(), path.clone());
        let during = case == "during record";
        SCRIPT.set(Some(Script {
            outcomes: Vec::new(),
            reached: Vec::new(),
            observe: Box::new(move |step| {
                if during && step == RecordStep::DirectoryOpen && !flag.get() {
                    std::fs::rename(&from, &to).unwrap();
                    flag.set(true);
                }
            }),
        }));
        let mut log = FileLog::new(path.clone()).unwrap();
        let recorded = log.record(&ours).map_err(|error| error.kind());
        SCRIPT.set(None);
        assert_eq!(recorded, Ok(()), "{case}: the record");
        assert_eq!(
            renamed.get(),
            during,
            "{case}: the rename point was reached"
        );
        if case == "after record" {
            std::fs::rename(&other, &path).unwrap();
        }
        let raise = log
            .raise(&raised, &[ours_key])
            .map_err(|error| error.kind());
        seen.push((case, raise, load()));
        std::fs::remove_file(&other).ok();
    }
    std::fs::remove_dir_all(&directory).unwrap();
    assert_eq!(
        seen,
        [
            (
                "during record",
                Err(std::io::ErrorKind::NotFound),
                Ok(theirs.clone())
            ),
            (
                "after record",
                Err(std::io::ErrorKind::NotFound),
                Ok(theirs)
            ),
            ("control", Ok(()), Ok(raised)),
        ],
        "each case: the raise and a later load of the path"
    );
}

/// A reload keeps the handle of the file it read for in-place raises, and returns that file's watermark as the
/// one the path holds. A file another writer renames over the path during the reload, here at the reload's
/// directory open, after its read, is the one a later load reads, so the reload refuses `NotFound` as a raise
/// does once the path names another file. The control renames nothing, and the reload returns the path's
/// watermark.
#[test]
fn a_rename_over_the_path_during_the_reload_refuses_the_reload() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::bind::record_step::{RecordStep, SCRIPT, Script};

    let directory = std::env::temp_dir().join(format!("watermark-reload-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let (path, other) = (directory.join("mark"), directory.join("other"));
    let marked = |shard, version| {
        let mut mark = Watermark::default();
        let key = Key::Page(Shard::new(shard).unwrap(), 0);
        assert_eq!(
            mark.observe(key, (Version::new(version).unwrap(), (7, 7))),
            Ok(true)
        );
        mark
    };
    let (ours, theirs) = (marked(1, 1), marked(2, 5));
    let mut seen = Vec::new();
    for during in [true, false] {
        for (at, mark) in [(&path, &ours), (&other, &theirs)] {
            FileLog::new(at.clone()).unwrap().record(mark).unwrap();
        }
        let renamed = Rc::new(Cell::new(false));
        let (flag, from, to) = (Rc::clone(&renamed), other.clone(), path.clone());
        SCRIPT.set(Some(Script {
            outcomes: Vec::new(),
            reached: Vec::new(),
            observe: Box::new(move |step| {
                if during && step == RecordStep::DirectoryOpen && !flag.get() {
                    std::fs::rename(&from, &to).unwrap();
                    flag.set(true);
                }
            }),
        }));
        let reloaded = FileLog::new(path.clone()).unwrap().reload();
        SCRIPT.set(None);
        assert_eq!(renamed.get(), during, "the rename point was reached");
        seen.push((during, reloaded.map_err(|error| error.kind())));
    }
    std::fs::remove_dir_all(&directory).unwrap();
    assert_eq!(
        seen,
        [(true, Err(std::io::ErrorKind::NotFound)), (false, Ok(ours))],
        "each case: whether a file was renamed over the path, and the reload"
    );
}
