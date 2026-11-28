//! The custody marker: its line for the arming, for each doubt of a final marker and for a case in
//! doubt alone, a write that fails, and its removal in each state the marker can be in. Each line,
//! each section's `quarantine` and each directory's entries are those the marker's rules give.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use kestrike_tools::fis_controller::{
    Failure, Marker, Moment, Opening, Progress, Section, Unremoved,
};
use kestrike_tools::host_stop::Disk;
use kestrike_tools::json::{Integer, Text, Value};

use crate::fis_support::steps::Steps;
use crate::fis_support::{Scratch, listing};

const BOOT: &str = "0123abcd-0123-4567-89ab-0123456789ab";
const AFTER: &str = "after the episode";

/// Each marker's line, by row.
const LINES: &[(&str, &str)] = &[
    (
        "armed",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (armed before the template's creation): experiment the unlisted start tagged start-T, template tagged request=template-R, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "armed-started",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (armed): experiment EXP1, template tagged request=None, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "armed-unbooted",
        r#"{"boot": null, "custody": "the FIS fault's end is unconfirmed (armed before the template's creation): experiment the unlisted start tagged start-T, template tagged request=template-R, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "during-custody-alone",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the case's custody is unknown (armed): killed", "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-binding",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS template tmpl-1 may remain and admits starts (after the episode); delete it or confirm the tag request=None lists none; the FIS fault's end is unconfirmed (after the episode): experiment EXP1, template tmpl-1, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-custody-alone",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the case's custody is unknown (after the episode): the lane was killed; its case may still hold the devices", "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-custody-and-fault",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (after the episode): experiment EXP1, template tagged request=None, start token start-T; the case's custody is unknown (after the episode): killed", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-everything",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS template tmpl-1 may remain and admits starts (after the episode); delete it or confirm the tag request=template-R lists none; the experiments of the deleted FIS template tmpl-1 are unconfirmed (after the episode): a listing failed; list the experiments under the template's ID and confirm each ended with the volume restored; the FIS fault's end is unconfirmed (after the episode): experiment EXP1, EXP3, the unlisted start tagged start-T, template tmpl-1, start token start-T; the case's custody is unknown (after the episode): the lane was killed", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-fault",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (after the episode): experiment EXP1, template tagged request=None, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-lost-creation",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS template tagged request=template-R may remain and admits starts (after the episode); delete it or confirm the tag request=template-R lists none", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-lost-gone",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (after the episode): experiment the unlisted start tagged start-T, template tagged request=template-R, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-restored",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS template tmpl-1 may remain and admits starts (after the episode); delete it or confirm the tag request=None lists none", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-retained",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS template tmpl-1 may remain and admits starts (after the episode); delete it or confirm the tag request=None lists none", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-start-token-missing",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (after the episode): experiment the unlisted start tagged None, template tagged request=None, start token None", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-start-unconfirmed",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (after the episode): experiment the unlisted start tagged start-T, template tagged request=None, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-template-experiments",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the experiments of the deleted FIS template tmpl-2 are unconfirmed (after the episode): ['EXP2', 'EXP3']; list the experiments under the template's ID and confirm each ended with the volume restored", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-template-unconfirmed",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS template tagged request=template-U may remain and admits starts (after the episode); delete it or confirm the tag request=template-U lists none", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-terminal",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (after the episode): experiment EXP3, template tagged request=None, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-unbound",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS template tmpl-1 may remain and admits starts (after the episode); delete it or confirm the tag request=None lists none; the FIS fault's end is unconfirmed (after the episode): experiment EXP1, template tmpl-1, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-unconfirmed",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (after the episode): experiment EXP1, EXP3, EXP4, template tagged request=None, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-unconfirmed-own",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS fault's end is unconfirmed (after the episode): experiment EXP3, EXP1, template tagged request=None, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
    (
        "final-unrestored",
        r#"{"boot": "0123abcd-0123-4567-89ab-0123456789ab", "custody": "the FIS template tmpl-1 may remain and admits starts (after the episode); delete it or confirm the tag request=None lists none; the FIS fault's end is unconfirmed (after the episode): experiment EXP1, template tmpl-1, start token start-T", "durable": true, "episode": "e1", "pgid": null, "profile": "p", "role": "r"}"#,
    ),
];

fn text(value: &str) -> Text {
    Text::from(value)
}

fn string(value: &str) -> Value {
    Value::String(text(value))
}

fn list(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|item| string(item)).collect())
}

/// A section as an episode's phases leave it: the start's and the template's tokens, then `members`.
fn section(members: &[(&str, Value)]) -> Section {
    let mut section = Section::new(Opening {
        profile: text("fis-read-latency"),
        episode: text("e1"),
        action: string("aws:ebs:volume-io-latency"),
        attachment: string("single"),
        targets: list(&["vol-1"]),
        test_timeout_io_us: Value::Null,
        production_timeout_io_us: Value::Null,
        kernel_nvme_io_timeout: None,
    });
    for (key, value) in [
        ("start_token", string("start-T")),
        ("template_token", string("template-R")),
    ]
    .into_iter()
    .chain(members.iter().cloned())
    {
        section.insert(key, value).expect("the key is the caller's");
    }
    section
}

/// One row: the note, the creation request's tag, the moment, whether the boot identity reads, the
/// episode and the section.
struct Row {
    note: &'static str,
    request: Option<&'static str>,
    moment: Moment,
    booted: bool,
    episode: Progress,
    section: Section,
}

fn row(name: &str) -> Row {
    let during = |note, request, members: &[(&str, Value)]| Row {
        note,
        request,
        moment: Moment::During,
        booted: true,
        episode: Progress::default(),
        section: section(members),
    };
    let fault = ("fault_end_unconfirmed", Value::Bool(true));
    let own = ("experiment_id", string("EXP1"));
    let retained = ("template_retained", string("tmpl-1"));
    let last = |episode: Progress, members: &[(&str, Value)]| Row {
        note: AFTER,
        request: None,
        moment: Moment::Final,
        booted: true,
        episode,
        section: section(members),
    };
    let started = Progress {
        experiment_id: Some(text("EXP1")),
        ..Progress::default()
    };
    let lost = Progress {
        lost_creation: Some(text("template-R")),
        ..Progress::default()
    };
    match name {
        "armed" => during(
            "armed before the template's creation",
            Some("template-R"),
            &[],
        ),
        "armed-unbooted" => Row {
            booted: false,
            ..during(
                "armed before the template's creation",
                Some("template-R"),
                &[],
            )
        },
        "armed-started" => Row {
            episode: started,
            ..during("armed", None, &[own])
        },
        "final-fault" => last(Progress::default(), &[fault, own]),
        "final-retained" => last(Progress::default(), &[fault, retained, own]),
        "final-lost-creation" => last(lost, &[fault]),
        "final-lost-gone" => last(
            Progress {
                template_gone: true,
                ..lost
            },
            &[fault],
        ),
        "final-template-experiments" => last(
            Progress::default(),
            &[
                fault,
                ("template_id", string("tmpl-2")),
                ("template_experiments_unconfirmed", list(&["EXP2", "EXP3"])),
                own,
            ],
        ),
        "final-unconfirmed" => last(
            started,
            &[
                fault,
                ("unconfirmed_experiments", list(&["EXP3", "EXP4"])),
                own,
            ],
        ),
        "final-unconfirmed-own" => last(
            started,
            &[fault, ("unconfirmed_experiments", list(&["EXP3", "EXP1"]))],
        ),
        "final-terminal" => last(
            Progress {
                terminal: true,
                ..started
            },
            &[fault, ("unconfirmed_experiments", list(&["EXP3"])), own],
        ),
        "final-start-unconfirmed" => last(
            Progress::default(),
            &[fault, ("start_unconfirmed", string("no listing answered"))],
        ),
        "final-unbound" => last(
            Progress::default(),
            &[fault, ("unbound_targets", list(&["arn"])), retained, own],
        ),
        "final-binding" => last(
            Progress::default(),
            &[
                fault,
                ("binding_unconfirmed", string("never read")),
                retained,
                own,
            ],
        ),
        "final-unrestored" | "final-restored" => last(
            Progress {
                requested: true,
                restoration: Some(name == "final-restored"),
                ..Progress::default()
            },
            &[fault, retained, own],
        ),
        "final-template-unconfirmed" => last(
            lost,
            &[fault, ("template_unconfirmed", string("template-U"))],
        ),
        "final-everything" => last(
            Progress {
                experiment_id: Some(text("EXP1")),
                lost_creation: Some(text("template-R")),
                requested: true,
                ..Progress::default()
            },
            &[
                fault,
                retained,
                (
                    "template_experiments_unconfirmed",
                    string("a listing failed"),
                ),
                ("unconfirmed_experiments", list(&["EXP3"])),
                ("start_unconfirmed", string("lost")),
                ("custody_unknown", string("the lane was killed")),
            ],
        ),
        "final-custody-alone" => last(
            Progress {
                terminal: true,
                ..started
            },
            &[
                (
                    "custody_unknown",
                    string("the lane was killed; its case may still hold the devices"),
                ),
                own,
            ],
        ),
        "during-custody-alone" => during("armed", None, &[("custody_unknown", string("killed"))]),
        "final-custody-and-fault" => last(
            Progress::default(),
            &[fault, ("custody_unknown", string("killed")), own],
        ),
        "final-start-token-missing" => {
            last(Progress::default(), &[fault, ("start_token", Value::Null)])
        }
        other => panic!("{other} is a row"),
    }
}

fn marker(custody: &Path, boot: PathBuf) -> Marker {
    Marker::new(
        custody.as_os_str(),
        OsStr::new("e1"),
        text("p"),
        text("r"),
        boot,
    )
}

/// The boot identity's file of a scratch directory, or a path where none stands.
fn boot(scratch: &Scratch, booted: bool) -> PathBuf {
    let path = scratch
        .path()
        .join(if booted { "boot_id" } else { "no-boot-id" });
    if booted {
        fs::write(&path, format!("{BOOT}\n")).expect("the boot identity is written");
    }
    path
}

/// Each marker's line names its doubts: the arming names the start by its token and the template by
/// its request tag; a final marker names each doubt apart, the fault's own as its last; a case in
/// doubt alone is not durable; and the section's `quarantine` names the marker once it stands.
#[test]
fn each_marker_names_its_doubts_in_its_line() {
    let scratch = Scratch::new("marker-lines");
    for (name, line) in LINES {
        let Row {
            note,
            request,
            moment,
            booted,
            episode,
            mut section,
        } = row(name);
        let custody = scratch.path().join(format!("custody-{name}"));
        let marker = marker(&custody, boot(&scratch, booted));
        let request = request.map(text);
        marker
            .write(
                &Disk,
                &mut section,
                &episode,
                note,
                request.as_ref(),
                moment,
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let written = fs::read_to_string(marker.path()).expect("the marker reads");
        assert_eq!(written, format!("{line}\n"), "{name}");
        let shown = format!("<d>/custody-{name}/fis-e1.json");
        assert_eq!(
            section.get("quarantine").map(|value| match value {
                Value::String(path) => scratch.norm(&path.to_string()),
                other => panic!("{other:?} is a path"),
            }),
            Some(shown),
            "{name}"
        );
        assert_eq!(
            listing(&custody),
            ["fis-e1.json"],
            "{name}: no partial stays"
        );
    }
}

/// A marker's write that fails returns the system's error and leaves the section without
/// `quarantine`: a link at the name is `ELOOP` and its target stays, and a directory at the name
/// fails the rename. The same episode with nothing at the name writes its marker.
#[test]
fn a_marker_that_cannot_be_written_returns_its_error_and_records_nothing() {
    let scratch = Scratch::new("marker-refused");
    let linked = scratch.path().join("custody-linked");
    fs::create_dir(&linked).expect("the directory is made");
    fs::write(linked.join("elsewhere"), "kept").expect("the target is written");
    symlink(linked.join("elsewhere"), linked.join("fis-e1.json")).expect("the link is made");
    let blocked = scratch.path().join("custody-directory");
    fs::create_dir_all(blocked.join("fis-e1.json")).expect("the directory is made");
    let free = scratch.path().join("custody-free");
    for (custody, error) in [
        (
            &linked,
            Some("[Errno 40] Too many levels of symbolic links: '<d>/custody-linked/fis-e1.json'"),
        ),
        (
            &blocked,
            Some(
                "[Errno 21] Is a directory: '<d>/custody-directory/fis-e1.json.partial' -> \
                 '<d>/custody-directory/fis-e1.json'",
            ),
        ),
        (&free, None),
    ] {
        let Row {
            note,
            episode,
            mut section,
            ..
        } = row("armed");
        let result = marker(custody, boot(&scratch, true)).write(
            &Disk,
            &mut section,
            &episode,
            note,
            Some(&text("template-R")),
            Moment::During,
        );
        match error {
            Some(error) => {
                let Err(Failure::System(got)) = result else {
                    panic!("{result:?} is a system error");
                };
                assert_eq!(scratch.norm(&got.to_string()), error);
                assert!(!section.contains("quarantine"), "nothing is recorded");
            }
            None => {
                assert_eq!(result, Ok(()));
                assert!(section.contains("quarantine"), "the control records it");
            }
        }
    }
    assert_eq!(
        fs::read_to_string(linked.join("elsewhere")).expect("reads"),
        "kept"
    );
}

/// An experiment to name that is no text is refused before anything is written.
#[test]
fn an_experiment_that_is_no_text_is_refused_before_the_write() {
    let scratch = Scratch::new("marker-unnamed");
    for (value, refused) in [
        (
            Value::Array(vec![Value::Integer(Integer::from(7u64))]),
            true,
        ),
        (Value::Integer(Integer::from(7u64)), true),
        (list(&["EXP7"]), false),
    ] {
        let custody = scratch.path().join(format!("custody-{refused}"));
        let Row {
            note,
            episode,
            mut section,
            ..
        } = row("final-fault");
        section
            .insert("unconfirmed_experiments", value)
            .expect("the key is the caller's");
        let result = marker(&custody, boot(&scratch, true)).write(
            &Disk,
            &mut section,
            &episode,
            note,
            None,
            Moment::Final,
        );
        assert_eq!(matches!(result, Err(Failure::Unreadable(_))), refused);
        assert_eq!(custody.exists(), !refused, "a refusal writes nothing");
    }
}

/// Whether the host stays released, the section's `quarantine` and the directory's entries.
type Left = (bool, String, Vec<String>);

fn left(released: bool, quarantine: impl Into<String>, names: &[&str]) -> Left {
    (
        released,
        quarantine.into(),
        names.iter().map(|name| (*name).to_owned()).collect(),
    )
}

/// The removal's outcome for the episode: a removal's error leaves the section as it was, which this
/// asserts, and the episode then records that the marker stays. Returns that outcome and the
/// directories opened to be synced.
fn removal(directory: &Path, marker: &Marker, files: &Steps, scratch: &Scratch) -> (Left, usize) {
    let mut section = section(&[]);
    section
        .insert("quarantine", Value::String(marker.shown().clone()))
        .expect("quarantine is the caller's");
    let released = match marker.remove(files, &mut section) {
        Ok(()) => true,
        Err(Unremoved::Removal(error)) => {
            assert_eq!(
                section.get("quarantine"),
                Some(&Value::String(marker.shown().clone())),
                "a failed removal leaves the section as it was"
            );
            let stays = format!("{} stays: {error}", marker.shown());
            section
                .insert("quarantine", Value::String(text(&stays)))
                .expect("quarantine is the caller's");
            false
        }
        Err(Unremoved::Check(error)) => panic!("the check fails: {error}"),
    };
    let quarantine = match section.get("quarantine") {
        Some(Value::String(text)) => scratch.norm(&text.to_string()),
        None => "<absent>".to_owned(),
        other => panic!("{other:?} is a quarantine"),
    };
    let opened = files.opened.borrow().len();
    ((released, quarantine, listing(directory)), opened)
}

const BOOTED: &str = "{\"boot\": \"0123abcd-0123-4567-89ab-0123456789ab\", \"custody\": \"x\", \"episode\": \
                      \"e1\", \"pgid\": null, \"profile\": \"p\", \"role\": \"r\"}\n";

/// What a removal row plants under the marker's directory before the removal.
type Plant = fn(&Path, &Path);

/// The removal in each state the marker can be in: an absent marker is no step, with no directory
/// synced, and keeps `quarantine`; an armed, a final durable and a boot-scoped marker, a link to a
/// file and a link to nothing are unlinked, the directory synced once, the link's target kept, and
/// `quarantine` dropped; a partial file of a killed write stays beside them; a directory at the name
/// fails the unlink, and a failed sync of the directory returns after the unlink stood, each with
/// the section untouched for the episode to record that the marker stays.
#[test]
fn a_marker_is_removed_in_each_state_it_can_stand_in() {
    let scratch = Scratch::new("marker-removal");
    let armed: Plant = |_, path| fs::write(path, format!("{}\n", line("armed"))).expect("written");
    let durable: Plant =
        |_, path| fs::write(path, format!("{}\n", line("final-fault"))).expect("written");
    let booted: Plant = |_, path| fs::write(path, BOOTED).expect("written");
    let linked: Plant = |directory, path| {
        fs::write(directory.join("elsewhere"), "kept").expect("written");
        symlink(directory.join("elsewhere"), path).expect("linked");
    };
    let dangling: Plant =
        |directory, path| symlink(directory.join("nowhere"), path).expect("linked");
    let partial: Plant = |directory, path| {
        fs::write(path, format!("{}\n", line("final-fault"))).expect("written");
        fs::write(directory.join("fis-e1.json.partial"), "{").expect("written");
    };
    let partial_alone: Plant =
        |directory, _| fs::write(directory.join("fis-e1.json.partial"), "{").expect("written");
    let blocked: Plant = |_, path| {
        fs::create_dir(path).expect("made");
        fs::write(path.join("inner"), "x").expect("written");
    };
    let nothing: Plant = |_, _| {};
    let shown = |name: &str| format!("<d>/remove-{name}/fis-e1.json");
    let rows: [(&str, Plant, bool, Left, usize); 10] = [
        (
            "absent",
            nothing,
            false,
            left(true, shown("absent"), &[]),
            0,
        ),
        ("armed", armed, false, left(true, "<absent>", &[]), 1),
        (
            "final-durable",
            durable,
            false,
            left(true, "<absent>", &[]),
            1,
        ),
        ("final-boot", booted, false, left(true, "<absent>", &[]), 1),
        (
            "link",
            linked,
            false,
            left(true, "<absent>", &["elsewhere"]),
            1,
        ),
        ("dangling", dangling, false, left(true, "<absent>", &[]), 1),
        (
            "partial",
            partial,
            false,
            left(true, "<absent>", &["fis-e1.json.partial"]),
            1,
        ),
        (
            "partial-alone",
            partial_alone,
            false,
            left(true, shown("partial-alone"), &["fis-e1.json.partial"]),
            0,
        ),
        (
            "directory",
            blocked,
            false,
            left(
                false,
                format!(
                    "{} stays: [Errno 21] Is a directory: '{}'",
                    shown("directory"),
                    shown("directory")
                ),
                &["fis-e1.json/"],
            ),
            0,
        ),
        (
            "sync",
            durable,
            true,
            left(
                false,
                format!("{} stays: [Errno 5] Input/output error", shown("sync")),
                &[],
            ),
            1,
        ),
    ];
    for (name, plant, failing_sync, want, opened) in rows {
        let directory = scratch.path().join(format!("remove-{name}"));
        fs::create_dir(&directory).expect("the directory is made");
        let marker = marker(&directory, directory.join("boot_id"));
        plant(&directory, marker.path());
        let files = Steps {
            directory_sync: failing_sync.then(|| directory.clone()),
            ..Steps::default()
        };
        let (got, synced) = removal(&directory, &marker, &files, &scratch);
        assert_eq!(got, want, "{name}");
        assert_eq!(synced, opened, "{name}: the directories synced");
    }
}

/// A check of the name that fails other than by an absence is the check's error, before any
/// removal: the marker stays and the section is unchanged. Control: the same marker with the check
/// succeeding is removed.
#[test]
fn a_failed_check_of_the_marker_removes_nothing() {
    let scratch = Scratch::new("marker-check");
    for failing in [true, false] {
        let directory = scratch.path().join(format!("check-{failing}"));
        fs::create_dir(&directory).expect("the directory is made");
        let marker = marker(&directory, directory.join("boot_id"));
        let files = Steps {
            lstat: failing.then(|| marker.path().to_path_buf()),
            ..Steps::default()
        };
        symlink(directory.join("nowhere"), marker.path()).expect("linked");
        let mut section = section(&[("quarantine", Value::String(marker.shown().clone()))]);
        let removed = marker.remove(&files, &mut section);
        if failing {
            let Err(Unremoved::Check(error)) = removed else {
                panic!("{removed:?} is the check's error");
            };
            assert_eq!(
                scratch.norm(&error.to_string()),
                "[Errno 13] Permission denied: '<d>/check-true/fis-e1.json'"
            );
            assert!(section.contains("quarantine"), "the section is unchanged");
            assert_eq!(listing(&directory), ["fis-e1.json@"], "the marker stays");
        } else {
            assert_eq!(removed, Ok(()));
            assert!(listing(&directory).is_empty(), "the control removes it");
        }
    }
}

/// The line `LINES` records for the row `name`.
fn line(name: &str) -> &'static str {
    LINES
        .iter()
        .find_map(|(row, line)| (*row == name).then_some(*line))
        .unwrap_or_else(|| panic!("{name} is a row of LINES"))
}
