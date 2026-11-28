//! The custody marker: its line for the arming, for each doubt of a final marker and for a case in
//! doubt alone, a write that fails, and its removal in each state the marker can be in. Each line,
//! each section's `quarantine` and each directory's entries are the script's on the same episode.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use kestrike_tools::fis_controller::{Failure, Marker, Moment, Opening, Progress, Section};
use kestrike_tools::host_stop::Disk;
use kestrike_tools::json::{Integer, Text, Value};

use crate::fis_support::steps::Steps;
use crate::fis_support::{Scratch, listing};

const BOOT: &str = "0123abcd-0123-4567-89ab-0123456789ab";
const AFTER: &str = "after the episode";

/// Each marker's line as the script writes it, by row.
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

/// Each marker's line is the script's: the arming names the start by its token and the template by
/// its request tag; a final marker names each doubt apart, the fault's own as its last; a case in
/// doubt alone is not durable; and the section's `quarantine` names the marker once it stands.
#[test]
fn each_marker_holds_the_line_the_script_writes() {
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

/// What a row's removal left: whether the host stays released, the section's `quarantine` as the
/// episode records it, and the directory's entries.
fn removal(
    scratch: &Scratch,
    name: &str,
    prepare: impl FnOnce(&Path, &Path),
    files: &Steps,
) -> Left {
    let directory = scratch.path().join(format!("remove-{name}"));
    fs::create_dir(&directory).expect("the directory is made");
    let marker = marker(&directory, directory.join("boot_id"));
    prepare(&directory, marker.path());
    let mut section = section(&[]);
    section
        .insert("quarantine", Value::String(marker.shown().clone()))
        .expect("quarantine is the caller's");
    let released = match marker.remove(files, &mut section) {
        Ok(()) => true,
        Err(error) => {
            let stays = format!("{} stays: {error}", marker.shown());
            section
                .insert("quarantine", Value::String(text(&stays)))
                .expect("quarantine is the caller's");
            false
        }
    };
    let quarantine = match section.get("quarantine") {
        Some(Value::String(text)) => scratch.norm(&text.to_string()),
        None => "<absent>".to_owned(),
        other => panic!("{other:?} is a quarantine"),
    };
    (released, quarantine, listing(&directory))
}

const DURABLE: &str = "{\"boot\": \"0123abcd-0123-4567-89ab-0123456789ab\", \"custody\": \"x\", \"durable\": true, \
                       \"episode\": \"e1\", \"pgid\": null, \"profile\": \"p\", \"role\": \"r\"}\n";
const BOOTED: &str = "{\"boot\": \"0123abcd-0123-4567-89ab-0123456789ab\", \"custody\": \"x\", \"episode\": \
                      \"e1\", \"pgid\": null, \"profile\": \"p\", \"role\": \"r\"}\n";

/// The removal in each state the marker can be in: an absent marker is no step and keeps
/// `quarantine`; an armed, a durable and a boot-scoped marker, a link to a file and a link to nothing
/// are unlinked, the link's target kept, and `quarantine` dropped; a partial file of a killed write
/// stays beside them; a directory at the name fails the unlink and a failed sync of the directory
/// returns after the unlink, each with `quarantine` untouched for the episode to record.
#[test]
fn a_marker_is_removed_in_each_state_as_the_script_removes_it() {
    let scratch = Scratch::new("marker-removal");
    let plain = Steps::default();
    let durable = |_: &Path, path: &Path| fs::write(path, DURABLE).expect("the marker is written");
    let shown = |name: &str| format!("<d>/remove-{name}/fis-e1.json");
    let partial =
        |directory: &Path| fs::write(directory.join("fis-e1.json.partial"), "{").expect("written");
    let rows: Vec<(&str, Left, Left)> = vec![
        (
            "absent",
            removal(&scratch, "absent", |_, _| {}, &plain),
            left(true, shown("absent"), &[]),
        ),
        (
            "armed",
            removal(&scratch, "armed", durable, &plain),
            left(true, "<absent>", &[]),
        ),
        (
            "final-durable",
            removal(&scratch, "final-durable", durable, &plain),
            left(true, "<absent>", &[]),
        ),
        (
            "final-boot",
            removal(
                &scratch,
                "final-boot",
                |_, path| fs::write(path, BOOTED).expect("written"),
                &plain,
            ),
            left(true, "<absent>", &[]),
        ),
        (
            "link",
            removal(
                &scratch,
                "link",
                |directory, path| {
                    fs::write(directory.join("elsewhere"), "kept").expect("written");
                    symlink(directory.join("elsewhere"), path).expect("linked");
                },
                &plain,
            ),
            left(true, "<absent>", &["elsewhere"]),
        ),
        (
            "dangling",
            removal(
                &scratch,
                "dangling",
                |directory, path| symlink(directory.join("nowhere"), path).expect("linked"),
                &plain,
            ),
            left(true, "<absent>", &[]),
        ),
        (
            "partial",
            removal(
                &scratch,
                "partial",
                |directory, path| {
                    durable(directory, path);
                    partial(directory);
                },
                &plain,
            ),
            left(true, "<absent>", &["fis-e1.json.partial"]),
        ),
        (
            "partial-alone",
            removal(
                &scratch,
                "partial-alone",
                |directory, _| partial(directory),
                &plain,
            ),
            left(true, shown("partial-alone"), &["fis-e1.json.partial"]),
        ),
        (
            "directory",
            removal(
                &scratch,
                "directory",
                |_, path| {
                    fs::create_dir(path).expect("made");
                    fs::write(path.join("inner"), "x").expect("written");
                },
                &plain,
            ),
            left(
                false,
                format!(
                    "{} stays: [Errno 21] Is a directory: '{}'",
                    shown("directory"),
                    shown("directory")
                ),
                &["fis-e1.json/"],
            ),
        ),
        (
            "sync",
            removal(
                &scratch,
                "sync",
                durable,
                &Steps {
                    directory_sync: Some(scratch.path().join("remove-sync")),
                    ..Steps::default()
                },
            ),
            left(
                false,
                format!("{} stays: [Errno 5] Input/output error", shown("sync")),
                &[],
            ),
        ),
    ];
    for (name, got, want) in rows {
        assert_eq!(got, want, "{name}");
    }
}
