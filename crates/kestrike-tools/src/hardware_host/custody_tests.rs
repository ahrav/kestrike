//! Each case builds its own process table and boot identity in a scratch directory and names both to the
//! read, so no case reads the host's `/proc`.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use super::{boot_id, held_custody};
use crate::paths::tests::Scratch;
use crate::text::Text;

const BOOT: &str = "0123abcd-0000-4000-8000-00000000beef";

/// A well-formed boot identity other than [`BOOT`].
const OTHER: &str = "ffffffff-0000-4000-8000-00000000beef";

/// Writes `<proc>/<pid>/stat` with the state, the group and the start time at fields 3, 5 and 22.
fn stat(proc: &Path, pid: u32, command: &str, state: &str, pgid: u32, start: u64) {
    threaded(proc, &pid.to_string(), command, state, pgid, start, 0);
}

/// Writes `<proc>/<name>/stat` of the process `name` with the state, the group, the count of threads
/// and the start time at fields 3, 5, 20 and 22.
fn threaded(
    proc: &Path,
    name: &str,
    command: &str,
    state: &str,
    pgid: u32,
    start: u64,
    threads: u32,
) {
    let pid = name;
    let mut fields = vec![state.to_owned(), "1".to_owned(), pgid.to_string()];
    fields.extend(std::iter::repeat_n("0".to_owned(), 16));
    fields[17] = threads.to_string();
    fields.extend([start.to_string(), "0".to_owned(), "0".to_owned()]);
    let directory = proc.join(name);
    fs::create_dir_all(&directory).expect("the process directory is made");
    fs::write(
        directory.join("stat"),
        format!("{pid} ({command}) {}\n", fields.join(" ")),
    )
    .expect("the record is written");
}

const WHERE: &str = r#""profile": "p", "role": "r", "episode": "e", "custody": "c""#;

/// A tree with a process table of a live leader 100 and its zombie 101, a group 200 whose leader ended
/// and whose stopped member 201 lives, a group 300 of a zombie alone, a process 400 that reused the
/// number of a recorded member, a stopped process 501 that left group 500 for group 600, a process 500
/// that ended after the listing, whose directory holds no `stat`, and an entry `self` that links to
/// the live leader's directory; and markers of each state.
fn tree(scratch: &Scratch) {
    let proc = scratch.0.join("proc");
    stat(&proc, 100, "lead er)", "S", 100, 5000);
    stat(&proc, 101, "z", "Z", 100, 5001);
    stat(&proc, 201, "child", "T", 200, 7000);
    stat(&proc, 300, "z", "Z", 300, 8000);
    stat(&proc, 400, "new", "R", 400, 9999);
    stat(&proc, 501, "moved", "T", 600, 7100);
    fs::create_dir(proc.join("500")).expect("made");
    symlink("100", proc.join("self")).expect("linked");
    fs::write(proc.join("abc"), "").expect("made");
    let custody = scratch.0.join("custody");
    fs::create_dir_all(custody.join("m1-dir.json")).expect("made");
    let markers = [
        ("m1-unreadable", "nope".to_owned()),
        (
            "m2-durable",
            format!(r#"{{{WHERE}, "pgid": 100, "durable": 1}}"#),
        ),
        (
            "m3-badboot",
            format!(
                r#"{{{WHERE}, "pgid": 100, "boot": "{}"}}"#,
                BOOT.to_uppercase()
            ),
        ),
        (
            "m4-otherboot",
            format!(r#"{{{WHERE}, "pgid": 100, "boot": "{OTHER}"}}"#),
        ),
        (
            "m5-nullpgid",
            format!(r#"{{{WHERE}, "pgid": null, "boot": "{BOOT}"}}"#),
        ),
        (
            "m6-zeropgid",
            format!(r#"{{{WHERE}, "pgid": 0, "boot": "{BOOT}"}}"#),
        ),
        (
            "m7-badmembers",
            format!(r#"{{{WHERE}, "pgid": 100, "boot": "{BOOT}", "members": {{"x": 1}}}}"#),
        ),
        (
            "m8-held",
            format!(r#"{{{WHERE}, "pgid": 100, "boot": "{BOOT}", "members": {{"100": 5000}}}}"#),
        ),
        (
            "m8-nomember",
            format!(r#"{{"pgid": 100, "boot": "{BOOT}", "members": {{}}}}"#),
        ),
        (
            "m8-leaderended",
            format!(r#"{{{WHERE}, "pgid": 200, "boot": "{BOOT}", "members": {{"200": 6000}}}}"#),
        ),
        (
            "m9-zombies",
            format!(r#"{{{WHERE}, "pgid": 300, "boot": "{BOOT}", "members": {{"300": 8000}}}}"#),
        ),
        (
            "m9-reused",
            format!(r#"{{{WHERE}, "pgid": 400, "boot": "{BOOT}", "members": {{"400": 4000}}}}"#),
        ),
        ("m1-empty", "{}".to_owned()),
        ("m1-list", "[1]".to_owned()),
        (
            "m2-notdurable",
            format!(
                r#"{{{WHERE}, "pgid": 300, "durable": false, "boot": "{BOOT}", "members": {{}}}}"#
            ),
        ),
        (
            "m2-durableoldboot",
            format!(r#"{{{WHERE}, "pgid": null, "durable": true, "boot": "{OTHER}"}}"#),
        ),
        (
            "m4-otherbootnull",
            format!(r#"{{{WHERE}, "pgid": null, "boot": "{OTHER}"}}"#),
        ),
        (
            "m4-otherbootzero",
            format!(r#"{{{WHERE}, "pgid": 0, "boot": "{OTHER}"}}"#),
        ),
        (
            "m6-truepgid",
            format!(r#"{{{WHERE}, "pgid": true, "boot": "{BOOT}", "members": {{}}}}"#),
        ),
        (
            "m6-stringpgid",
            format!(r#"{{{WHERE}, "pgid": "4343", "boot": "{BOOT}", "members": {{}}}}"#),
        ),
        (
            "m7-absent",
            format!(r#"{{{WHERE}, "pgid": 300, "boot": "{BOOT}"}}"#),
        ),
        (
            "m7-string",
            format!(r#"{{{WHERE}, "pgid": 300, "boot": "{BOOT}", "members": "x"}}"#),
        ),
        (
            "m7-leadingzero",
            format!(r#"{{{WHERE}, "pgid": 300, "boot": "{BOOT}", "members": {{"0300": 8000}}}}"#),
        ),
        (
            "m7-zerostart",
            format!(r#"{{{WHERE}, "pgid": 300, "boot": "{BOOT}", "members": {{"300": 0}}}}"#),
        ),
        (
            "m7-truestart",
            format!(r#"{{{WHERE}, "pgid": 300, "boot": "{BOOT}", "members": {{"300": true}}}}"#),
        ),
        (
            "m7-floatstart",
            format!(r#"{{{WHERE}, "pgid": 300, "boot": "{BOOT}", "members": {{"300": 1.5}}}}"#),
        ),
        (
            "m8-moved",
            format!(r#"{{{WHERE}, "pgid": 500, "boot": "{BOOT}", "members": {{"501": 7100}}}}"#),
        ),
        (
            "m9-movedother",
            format!(r#"{{{WHERE}, "pgid": 500, "boot": "{BOOT}", "members": {{"501": 7101}}}}"#),
        ),
    ];
    for (name, body) in markers {
        fs::write(custody.join(format!("{name}.json")), body).expect("the marker is written");
    }
    fs::write(scratch.0.join("boot"), format!("{BOOT}\n")).expect("the boot identity is written");
}

fn left(custody: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(custody)
        .expect("the directory lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .collect();
    names.sort();
    names
}

/// `path` with `suffix` added to its text.
fn spelled(path: &Path, suffix: &str) -> PathBuf {
    let mut text = path.as_os_str().to_owned();
    text.push(suffix);
    PathBuf::from(text)
}

/// Each state gives its text, and only the markers of another boot (state 4, a null or zero `pgid`
/// included) and of a group no process of which holds memory (state 9) are removed: a group of
/// zombies alone, with members recorded or with none, a recorded member whose pid another process
/// reused, and a recorded member that left the group with another start time. A durable marker of
/// another boot holds. A group whose leader ended holds through its stopped descendant, and a stopped
/// recorded member that left for another group holds by its own start time, where the same member with
/// another start time is removed. An entry `self` of the process table is no process, though it reads
/// as the live leader. The custody directory spelled with `//./` names each marker by its pure path,
/// and the boot identity read through `<boot>/.` is the file's; the state-3 text names that spelling.
#[test]
fn a_marker_is_removed_in_states_four_and_nine_alone() {
    let scratch = Scratch::new("custody-states");
    tree(&scratch);
    let root = scratch.0.display().to_string();
    let held = held_custody(
        &spelled(&scratch.0.join("custody"), "//./"),
        &scratch.0.join("proc"),
        &spelled(&scratch.0.join("boot"), "/."),
    )
    .expect("the markers are judged");
    let judged = "the boot identity at ROOT/boot/. or the one the marker records is unreadable, so \
                  the marker is judged held";
    let expected = [
        "ROOT/custody/m1-dir.json (unreadable)".to_owned(),
        "ROOT/custody/m1-empty.json (unreadable)".to_owned(),
        "ROOT/custody/m1-list.json (unreadable)".to_owned(),
        "ROOT/custody/m1-unreadable.json (unreadable)".to_owned(),
        "p/r (episode e): c; remove ROOT/custody/m2-durable.json once the hazard is confirmed over"
            .to_owned(),
        "p/r (episode e): c; remove ROOT/custody/m2-durableoldboot.json once the hazard is confirmed \
         over"
            .to_owned(),
        format!("ROOT/custody/m3-badboot.json ({judged})"),
        "an unknown group of p/r (episode e): c; remove ROOT/custody/m5-nullpgid.json once its case is \
         contained"
            .to_owned(),
        "ROOT/custody/m6-stringpgid.json (unreadable process group '4343')".to_owned(),
        "ROOT/custody/m6-truepgid.json (unreadable process group True)".to_owned(),
        "ROOT/custody/m6-zeropgid.json (unreadable process group 0)".to_owned(),
        "ROOT/custody/m7-absent.json (unreadable members)".to_owned(),
        "ROOT/custody/m7-badmembers.json (unreadable members)".to_owned(),
        "ROOT/custody/m7-floatstart.json (unreadable members)".to_owned(),
        "ROOT/custody/m7-leadingzero.json (unreadable members)".to_owned(),
        "ROOT/custody/m7-string.json (unreadable members)".to_owned(),
        "ROOT/custody/m7-truestart.json (unreadable members)".to_owned(),
        "ROOT/custody/m7-zerostart.json (unreadable members)".to_owned(),
        "process group 100 of p/r (episode e): c".to_owned(),
        "process group 200 of p/r (episode e): c".to_owned(),
        "process group 500 of p/r (episode e): c".to_owned(),
        "process group 100 of None/None (episode None): None; ROOT/custody/m8-nomember.json records no \
         member, so identify the group before containing it"
            .to_owned(),
    ]
    .map(|line| Text::from(line.replace("ROOT", &root)));
    assert_eq!(held, expected);
    assert_eq!(
        left(&scratch.0.join("custody")),
        [
            "m1-dir.json",
            "m1-empty.json",
            "m1-list.json",
            "m1-unreadable.json",
            "m2-durable.json",
            "m2-durableoldboot.json",
            "m3-badboot.json",
            "m5-nullpgid.json",
            "m6-stringpgid.json",
            "m6-truepgid.json",
            "m6-zeropgid.json",
            "m7-absent.json",
            "m7-badmembers.json",
            "m7-floatstart.json",
            "m7-leadingzero.json",
            "m7-string.json",
            "m7-truestart.json",
            "m7-zerostart.json",
            "m8-held.json",
            "m8-leaderended.json",
            "m8-moved.json",
            "m8-nomember.json",
        ]
    );
}

/// Without a readable boot identity every readable marker that is not durable holds with a text naming
/// the identity's path, and none is removed; the same tree with the identity removes seven.
#[test]
fn no_boot_identity_holds_every_marker() {
    let scratch = Scratch::new("custody-noboot");
    tree(&scratch);
    let root = scratch.0.display().to_string();
    let custody = scratch.0.join("custody");
    let held = held_custody(&custody, &scratch.0.join("proc"), &scratch.0.join("absent"))
        .expect("the markers are judged");
    let judged = |name: &str| {
        Text::from(format!(
            "{root}/custody/{name}.json (the boot identity at {root}/absent or the one the marker records \
             is unreadable, so the marker is judged held)"
        ))
    };
    let mut expected = ["m1-dir", "m1-empty", "m1-list", "m1-unreadable"]
        .map(|name| Text::from(format!("{root}/custody/{name}.json (unreadable)")))
        .to_vec();
    for name in ["m2-durable", "m2-durableoldboot"] {
        expected.push(Text::from(format!(
            "p/r (episode e): c; remove {root}/custody/{name}.json once the hazard is confirmed over"
        )));
    }
    expected.extend(
        [
            "m2-notdurable",
            "m3-badboot",
            "m4-otherboot",
            "m4-otherbootnull",
            "m4-otherbootzero",
            "m5-nullpgid",
            "m6-stringpgid",
            "m6-truepgid",
            "m6-zeropgid",
            "m7-absent",
            "m7-badmembers",
            "m7-floatstart",
            "m7-leadingzero",
            "m7-string",
            "m7-truestart",
            "m7-zerostart",
            "m8-held",
            "m8-leaderended",
            "m8-moved",
            "m8-nomember",
            "m9-movedother",
            "m9-reused",
            "m9-zombies",
        ]
        .map(judged),
    );
    assert_eq!(held, expected);
    assert_eq!(left(&custody).len(), 29);
    held_custody(&custody, &scratch.0.join("proc"), &scratch.0.join("boot"))
        .expect("the markers are judged");
    assert_eq!(left(&custody).len(), 22);
}

/// An absent custody directory, and one whose names hold no `.json`, give none.
#[test]
fn an_absent_directory_gives_none() {
    let scratch = Scratch::new("custody-absent");
    fs::write(scratch.0.join("boot"), BOOT).expect("written");
    fs::create_dir(scratch.0.join("proc")).expect("made");
    let judged = |directory: &Path| {
        held_custody(directory, &scratch.0.join("proc"), &scratch.0.join("boot")).expect("judged")
    };
    assert!(judged(&scratch.0.join("absent")).is_empty());
    fs::write(scratch.0.join("other.txt"), "nope").expect("written");
    assert!(judged(&scratch.0).is_empty());
    fs::write(scratch.0.join("x.json"), "nope").expect("written");
    assert_eq!(judged(&scratch.0).len(), 1);
}

/// The boot identity is the file's text stripped of whitespace when it is a lower-case UUID, and none
/// for an absent file or any other shape.
#[test]
fn the_boot_identity_is_a_lower_case_uuid() {
    let scratch = Scratch::new("custody-boot");
    let path = scratch.0.join("boot_id");
    assert_eq!(boot_id(&path), None);
    for (text, expected) in [
        (format!(" {BOOT}\r\n"), Some(BOOT)),
        (BOOT.to_uppercase(), None),
        (format!("{BOOT}x"), None),
        (BOOT.replace('-', "_"), None),
        (String::new(), None),
    ] {
        fs::write(&path, text).expect("written");
        assert_eq!(boot_id(&path), expected.map(Text::from));
    }
}

/// A `stat` record outside UTF-8 ends the read with an error once a marker reaches the process table,
/// and the same record in UTF-8 is read.
#[test]
fn a_stat_record_outside_utf8_ends_the_read() {
    let scratch = Scratch::new("custody-undecodable");
    let proc = scratch.0.join("proc");
    stat(&proc, 100, "ok", "S", 100, 5000);
    fs::create_dir(proc.join("101")).expect("made");
    fs::write(proc.join("101/stat"), b"101 (\xff) S 1 100 0 0").expect("written");
    let custody = scratch.0.join("custody");
    fs::create_dir(&custody).expect("made");
    fs::write(
        custody.join("m.json"),
        format!(r#"{{"pgid": 100, "boot": "{BOOT}", "members": {{}}}}"#),
    )
    .expect("written");
    fs::write(scratch.0.join("boot"), BOOT).expect("written");
    let judged = || held_custody(&custody, &proc, &scratch.0.join("boot"));
    assert!(
        matches!(judged(), Err(super::CustodyError::Undecodable(path)) if path == proc.join("101/stat"))
    );
    fs::write(proc.join("101/stat"), b"101 (x) S 1 100 0 0").expect("written");
    assert_eq!(judged().expect("judged").len(), 1);
}

/// A custody directory whose listing is refused for permission gives no marker, as one with no marker
/// does, while the same directory open to listing gives its marker held. A process with the
/// capability to read any directory lists it anyway, so the case holds for other processes alone.
#[test]
fn a_refused_listing_gives_no_marker() {
    let scratch = Scratch::new("custody-refused");
    fs::create_dir(scratch.0.join("proc")).expect("made");
    fs::write(scratch.0.join("boot"), BOOT).expect("written");
    let custody = scratch.0.join("custody");
    fs::create_dir(&custody).expect("made");
    fs::write(custody.join("m.json"), "nope").expect("written");
    let judged = || {
        held_custody(&custody, &scratch.0.join("proc"), &scratch.0.join("boot")).expect("judged")
    };
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o300)).expect("mode");
    if fs::read_dir(&custody).is_ok() {
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("mode");
        eprintln!("skipped: this process lists a directory of mode 0300, so no listing is refused");
        return;
    }
    let refused = judged();
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("mode");
    assert!(refused.is_empty());
    assert_eq!(judged().len(), 1);
}

/// A scratch tree of one current-boot marker `m.json` holding `marker` and a process table, judged
/// through [`held_custody`].
struct One {
    scratch: Scratch,
}

impl One {
    fn new(label: &str, marker: &str) -> Self {
        let scratch = Scratch::new(label);
        fs::create_dir(scratch.0.join("proc")).expect("made");
        fs::create_dir(scratch.0.join("custody")).expect("made");
        fs::write(scratch.0.join("boot"), BOOT).expect("written");
        fs::write(scratch.0.join("custody/m.json"), marker).expect("written");
        Self { scratch }
    }

    fn proc(&self) -> PathBuf {
        self.scratch.0.join("proc")
    }

    fn judged(&self) -> Result<Vec<Text>, super::CustodyError> {
        held_custody(
            &self.scratch.0.join("custody"),
            &self.proc(),
            &self.scratch.0.join("boot"),
        )
    }

    fn stands(&self) -> bool {
        self.scratch.0.join("custody/m.json").exists()
    }
}

fn group(pgid: u32, members: &str) -> String {
    format!(r#"{{{WHERE}, "pgid": {pgid}, "boot": "{BOOT}", "members": {{{members}}}}}"#)
}

/// The leader of a thread group reads `Z` once its own thread ends, while other threads of it run, and
/// the read counts it as ended: a marker whose group holds only such a leader is removed, as one whose
/// leader is a single-thread zombie is, while the same leader in state `S` holds the marker.
#[test]
fn a_zombie_leader_with_running_threads_counts_as_ended() {
    for (state, threads, held) in [("Z", 2, false), ("Z", 1, false), ("S", 2, true)] {
        let one = One::new("custody-threads", &group(300, r#""300": 8000"#));
        threaded(&one.proc(), "300", "z", state, 300, 8000, threads);
        let judged = one.judged().expect("judged");
        assert_eq!(!judged.is_empty(), held, "{state} with {threads} threads");
        assert_eq!(one.stands(), held, "{state} with {threads} threads");
    }
}

/// A `stat` record that fails to read for a reason other than an absent process, a directory at its
/// name here, counts as no process: a marker whose one live member's record so fails is removed, while
/// the same member with a readable record holds it.
#[test]
fn a_stat_record_that_fails_to_read_counts_as_no_process() {
    for readable in [false, true] {
        let one = One::new("custody-stat-error", &group(800, r#""800": 1"#));
        if readable {
            stat(&one.proc(), 800, "live", "S", 800, 1);
        } else {
            fs::create_dir_all(one.proc().join("800/stat")).expect("made");
        }
        let judged = one.judged().expect("judged");
        assert_eq!(judged.len(), usize::from(readable), "readable {readable}");
        assert_eq!(one.stands(), readable, "readable {readable}");
    }
}

/// A process-table entry named with a digit Unicode assigned after 13.0, U+11F51, is no process and
/// leaves the group empty, so the marker is removed; one named with the older digit U+0661 is the
/// process 1 and holds the marker.
#[test]
fn an_entry_name_takes_the_digits_of_unicode_13() {
    for (name, held) in [("\u{11f51}", false), ("\u{661}", true)] {
        let one = One::new("custody-digits", &group(900, ""));
        threaded(&one.proc(), name, "x", "S", 900, 1, 0);
        let judged = one.judged().expect("judged");
        assert_eq!(judged.len(), usize::from(held), "{name:?}");
        assert_eq!(one.stands(), held, "{name:?}");
    }
}

/// A process table that cannot be listed, and a live member's `stat` record whose group field reads as
/// no integer, end the read with an error and leave the marker; a table that lists and reads judges it.
#[test]
fn an_unreadable_process_table_ends_the_read() {
    let one = One::new("custody-processes", &group(100, ""));
    fs::remove_dir(one.proc()).expect("removed");
    assert!(matches!(
        one.judged(),
        Err(super::CustodyError::Processes(_))
    ));
    assert!(one.stands());
    fs::create_dir(one.proc()).expect("made");
    let record = format!("7 (x) S 1 x{}\n", " 0".repeat(19));
    fs::create_dir(one.proc().join("7")).expect("made");
    fs::write(one.proc().join("7/stat"), record).expect("written");
    assert!(matches!(
        one.judged(),
        Err(super::CustodyError::Number(field)) if field == "x"
    ));
    assert!(one.stands());
    stat(&one.proc(), 7, "x", "S", 100, 1);
    assert_eq!(one.judged().expect("judged").len(), 1);
}

/// A marker that would be removed holds as unreadable once a byte outside UTF-8 stands inside one of
/// its strings, and stays; a member key of 4,301 digits ends the read with an error and leaves the
/// marker.
#[test]
fn an_undecodable_marker_holds_and_an_overlong_member_key_ends_the_read() {
    let one = One::new("custody-marker-bytes", "");
    let marker = one.scratch.0.join("custody/m.json");
    let mut bytes = format!(r#"{{"pgid": 1, "boot": "{OTHER}", "note": ""#).into_bytes();
    bytes.extend_from_slice(b"\xff\"}");
    fs::write(&marker, bytes).expect("written");
    let judged = one.judged().expect("judged");
    assert_eq!(
        judged,
        [Text::from(format!("{} (unreadable)", marker.display()))]
    );
    assert!(one.stands());
    let key = format!("1{}", "0".repeat(4300));
    fs::write(&marker, group(100, &format!(r#""{key}": 1"#))).expect("written");
    assert!(matches!(
        one.judged(),
        Err(super::CustodyError::Number(digits)) if digits.to_str() == Some(key.as_str())
    ));
    assert!(one.stands());
}

/// A removal that fails is passed over: in a custody directory that refuses a removal, the markers of
/// states 4 and 9 stay and the read gives none; in the same directory open to writing both go. A
/// process with the capability to write any directory removes them anyway, so the case holds for
/// other processes alone.
#[test]
fn a_failed_removal_is_passed_over() {
    let one = One::new("custody-removal", &group(300, ""));
    let custody = one.scratch.0.join("custody");
    fs::write(
        custody.join("o.json"),
        format!(r#"{{"pgid": 1, "boot": "{OTHER}"}}"#),
    )
    .expect("written");
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o500)).expect("mode");
    if fs::write(custody.join("probe"), "").is_ok() {
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("mode");
        eprintln!("skipped: this process writes a directory of mode 0500, so no removal fails");
        return;
    }
    let refused = one.judged();
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("mode");
    assert!(refused.expect("judged").is_empty());
    assert_eq!(left(&custody), ["m.json", "o.json"]);
    assert!(one.judged().expect("judged").is_empty());
    assert!(left(&custody).is_empty());
}

/// A `pgid` string holding U+0378, a code point unassigned in Unicode, holds the marker with the code
/// point written as it stands inside the quoted value.
#[test]
fn an_unassigned_code_point_stands_in_the_text() {
    let one = One::new(
        "custody-unassigned",
        &format!(r#"{{"pgid": "\u0378", "boot": "{BOOT}", "members": {{}}}}"#),
    );
    let marker = one.scratch.0.join("custody/m.json");
    assert_eq!(
        one.judged().expect("judged"),
        [Text::from(format!(
            "{} (unreadable process group '\u{378}')",
            marker.display()
        ))]
    );
    assert!(one.stands());
}
