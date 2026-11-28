//! The expected texts and removals were recorded from the hardware lane's custody read on the same
//! tree, with its boot identity's path set to the tree's file and its two readers of `/proc` pointed at
//! the tree's process table. Each case builds its own process table and boot identity.

use std::fs;
use std::path::Path;

use super::{boot_id, held_custody};
use crate::paths::tests::Scratch;
use crate::text::Text;

const BOOT: &str = "0123abcd-0000-4000-8000-00000000beef";

/// Writes `<proc>/<pid>/stat` with the state, the group and the start time at fields 3, 5 and 22.
fn stat(proc: &Path, pid: u32, command: &str, state: &str, pgid: u32, start: u64) {
    let mut fields = vec![state.to_owned(), "1".to_owned(), pgid.to_string()];
    fields.extend(std::iter::repeat_n("0".to_owned(), 16));
    fields.extend([start.to_string(), "0".to_owned(), "0".to_owned()]);
    let directory = proc.join(pid.to_string());
    fs::create_dir_all(&directory).expect("the process directory is made");
    fs::write(
        directory.join("stat"),
        format!("{pid} ({command}) {}\n", fields.join(" ")),
    )
    .expect("the record is written");
}

const WHERE: &str = r#""profile": "p", "role": "r", "episode": "e", "custody": "c""#;

/// A tree with a process table of a live leader 100 and its zombie 101, a group 200 whose leader ended
/// and whose member 201 lives, a group 300 of a zombie alone, and a process 400 that reused the number
/// of a recorded member; and one marker of each state.
fn tree(scratch: &Scratch) {
    let proc = scratch.0.join("proc");
    stat(&proc, 100, "lead er)", "S", 100, 5000);
    stat(&proc, 101, "z", "Z", 100, 5001);
    stat(&proc, 201, "child", "S", 200, 7000);
    stat(&proc, 300, "z", "Z", 300, 8000);
    stat(&proc, 400, "new", "R", 400, 9999);
    fs::create_dir(proc.join("self")).expect("made");
    fs::write(proc.join("abc"), "").expect("made");
    let custody = scratch.0.join("custody");
    fs::create_dir(&custody).expect("made");
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
            format!(r#"{{{WHERE}, "pgid": 100, "boot": "ffffffff-0000-4000-8000-00000000beef"}}"#),
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

/// Each state gives the lane's text, and only the markers of another boot (state 4), of a group of
/// zombies alone and of a group whose recorded member's pid another process reused (state 9) are
/// removed. The marker of a group whose leader ended holds through the live descendant, and a group
/// that still holds memory keeps its marker where the zombie group, differing in that one record,
/// loses it.
#[test]
fn a_marker_is_removed_in_states_four_and_nine_alone() {
    let scratch = Scratch::new("custody-states");
    tree(&scratch);
    let root = scratch.0.display().to_string();
    let held = held_custody(
        &scratch.0.join("custody"),
        &scratch.0.join("proc"),
        &scratch.0.join("boot"),
    )
    .expect("the markers are judged");
    let expected = [
        "ROOT/custody/m1-unreadable.json (unreadable)",
        "p/r (episode e): c; remove ROOT/custody/m2-durable.json once the hazard is confirmed over",
        "ROOT/custody/m3-badboot.json (the boot identity at ROOT/boot or the one the marker records is \
         unreadable, so the marker is judged held)",
        "an unknown group of p/r (episode e): c; remove ROOT/custody/m5-nullpgid.json once its case is \
         contained",
        "ROOT/custody/m6-zeropgid.json (unreadable process group 0)",
        "ROOT/custody/m7-badmembers.json (unreadable members)",
        "process group 100 of p/r (episode e): c",
        "process group 200 of p/r (episode e): c",
        "process group 100 of None/None (episode None): None; ROOT/custody/m8-nomember.json records no \
         member, so identify the group before containing it",
    ]
    .map(|line| Text::from(line.replace("ROOT", &root)));
    assert_eq!(held, expected);
    assert_eq!(
        left(&scratch.0.join("custody")),
        [
            "m1-unreadable.json",
            "m2-durable.json",
            "m3-badboot.json",
            "m5-nullpgid.json",
            "m6-zeropgid.json",
            "m7-badmembers.json",
            "m8-held.json",
            "m8-leaderended.json",
            "m8-nomember.json",
        ]
    );
}

/// Without a readable boot identity every marker past state 2 holds with the lane's text naming the
/// identity's path, and none is removed; the same tree with the identity removes three.
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
    let mut expected = vec![
        Text::from(format!("{root}/custody/m1-unreadable.json (unreadable)")),
        Text::from(format!(
            "p/r (episode e): c; remove {root}/custody/m2-durable.json once the hazard is confirmed over"
        )),
    ];
    expected.extend(
        [
            "m3-badboot",
            "m4-otherboot",
            "m5-nullpgid",
            "m6-zeropgid",
            "m7-badmembers",
            "m8-held",
            "m8-leaderended",
            "m8-nomember",
            "m9-reused",
            "m9-zombies",
        ]
        .map(judged),
    );
    assert_eq!(held, expected);
    assert_eq!(left(&custody).len(), 12);
    held_custody(&custody, &scratch.0.join("proc"), &scratch.0.join("boot"))
        .expect("the markers are judged");
    assert_eq!(left(&custody).len(), 9);
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
