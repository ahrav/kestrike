//! One plant's checks: its two files, its record's fields and rules in their order, its patch, and its
//! bytes against the head commit. Each row changes the working tree of `alpha` alone, and each refusal
//! leaves no path made and `git status` as it was.

use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command;

use kestrike_tools::json::Value;
use kestrike_tools::plants::Outcome;
use kestrike_tools::text::Text;

use super::repository::{
    Change, LIB, Repository, chmod, is_root, members, patch, record, replaced, write,
};

const JSON: &str = "verification/plants/alpha/plant.json";
const PATCH: &str = "verification/plants/alpha/plant.patch";

fn refused_with(repository: &Repository, reason: &str) {
    assert_eq!(
        repository.refused(&repository.call(&[])),
        format!("rejected: {reason}")
    );
}

/// `rows` runs each row in a fixture of its own: the row's change, then the checks, which must refuse
/// with `alpha: ` and the row's reason.
fn rows(rows: &[(&str, Change)]) {
    for (reason, change) in rows {
        let repository = Repository::new();
        change(&repository);
        refused_with(&repository, &format!("alpha: {reason}"));
    }
}

const BOTH: &str = "plant.json and plant.patch are both required, as regular files";

/// A missing file, a link and a directory in place of either file refuse the pair with one reason.
#[test]
fn each_file_must_be_a_regular_file() {
    rows(&[
        (BOTH, &|r| fs::remove_file(r.path(JSON)).expect("removed")),
        (BOTH, &|r| fs::remove_file(r.path(PATCH)).expect("removed")),
        (BOTH, &|r| {
            fs::remove_file(r.path(JSON)).expect("removed");
            fs::create_dir(r.path(JSON)).expect("made");
        }),
        (BOTH, &|r| {
            let kept = r.scratch.join("kept.json");
            fs::rename(r.path(JSON), &kept).expect("moved");
            symlink(&kept, r.path(JSON)).expect("linked");
        }),
        (BOTH, &|r| {
            fs::remove_file(r.path(PATCH)).expect("removed");
            fs::create_dir(r.path(PATCH)).expect("made");
        }),
        (BOTH, &|r| {
            let kept = r.scratch.join("kept.patch");
            fs::rename(r.path(PATCH), &kept).expect("moved");
            symlink(&kept, r.path(PATCH)).expect("linked");
        }),
    ]);
}

/// A file the user cannot read refuses with the operating system's text alone.
#[test]
fn an_unreadable_file_names_the_operating_systems_text() {
    if is_root() {
        return;
    }
    rows(&[
        ("plant.json is unreadable: Permission denied", &|r| {
            chmod(&r.path(JSON), 0o000)
        }),
        ("plant.patch is unreadable: Permission denied", &|r| {
            chmod(&r.path(PATCH), 0o000)
        }),
    ]);
}

/// A file of one byte more than 1 MiB is refused before the record is read; a record of exactly 1 MiB is
/// read, and refused only as a store that differs from the head.
#[test]
fn each_file_holds_at_most_one_mebibyte() {
    rows(&[
        (
            "plant.json or plant.patch holds more than 1048576 bytes",
            &|r| {
                r.write(JSON, " ".repeat((1 << 20) + 1));
            },
        ),
        (
            "plant.json or plant.patch holds more than 1048576 bytes",
            &|r| {
                r.write(PATCH, "x".repeat((1 << 20) + 1));
            },
        ),
    ]);
    let repository = Repository::new();
    let mut padded = record(&members("alpha", "src/lib.rs"));
    padded.push_str(&" ".repeat((1 << 20) - padded.len()));
    repository.write(JSON, padded);
    refused_with(
        &repository,
        "the plant store differs from HEAD at verification/plants/alpha/plant.json; commit the plants first",
    );
}

/// A repeated member of any object refuses the record with the member's name, the first to repeat in the
/// first object to close.
#[test]
fn a_repeated_member_refuses_the_record() {
    let mut repeated = members("alpha", "src/lib.rs");
    repeated.insert(3, ("row".to_owned(), "8".to_owned()));
    repeated.insert(4, ("id".to_owned(), "\"alpha\"".to_owned()));
    rows(&[
        ("plant.json is unreadable: repeated member row", &|r| {
            r.write(JSON, record(&repeated))
        }),
        ("plant.json is unreadable: repeated member commit", &|r| {
            r.write(
                JSON,
                replaced(
                    "fix",
                    "{\"commit\": \"a\", \"pull_request\": 1, \"commit\": \"b\"}",
                ),
            );
        }),
        ("plant.json is unreadable: repeated member cause", &|r| {
            let cause = "{\"cause\": \"workload\", \"evidence\": \"e\", \"cause\": \"ordering\"}";
            r.write(JSON, replaced("miss_cause", cause));
        }),
    ]);
}

/// Text that is no JSON document, or bytes that are no UTF-8, refuse the record with the reader's text.
#[test]
fn an_unreadable_record_names_the_readers_text() {
    rows(&[
        (
            "plant.json is unreadable: expected a value at byte 0",
            &|r| r.write(JSON, ""),
        ),
        (
            "plant.json is unreadable: expected ',' or '}' at byte 9",
            &|r| r.write(JSON, "{\"id\": 1 2}"),
        ),
        (
            "plant.json is unreadable: text after the value at byte 3",
            &|r| r.write(JSON, "{} {}"),
        ),
        (
            "plant.json is unreadable: invalid utf-8 sequence of 1 bytes from index 1",
            &|r| r.write(JSON, b"\"\xff\""),
        ),
        (
            "plant.json is unreadable: nesting deeper than the reader takes at byte 1000",
            &|r| r.write(JSON, "[".repeat(1001)),
        ),
    ]);
}

const FIELDS: &str = "plant.json holds exactly the fields id, row, fix, files, restores, proof, \
                      expected, miss_cause";

/// The record is one object of the eight fields, each once.
#[test]
fn the_record_holds_exactly_the_eight_fields() {
    let mut extra = members("alpha", "src/lib.rs");
    extra.push(("note".to_owned(), "1".to_owned()));
    let mut short = members("alpha", "src/lib.rs");
    short.pop();
    rows(&[
        (FIELDS, &|r| r.write(JSON, "[]")),
        (FIELDS, &|r| r.write(JSON, "null")),
        (FIELDS, &|r| r.write(JSON, record(&extra))),
        (FIELDS, &|r| r.write(JSON, record(&short))),
    ]);
}

const ID: &str = "id names the plant's directory in printable ASCII without edge spaces, so campaign takes \
                  plant-<id>";
const ROW: &str = "row is a positive integer";
const FIX: &str = "fix holds a positive pull_request and a commit";
const FILES: &str = "files is a nonempty list of paths";
const TEXT: &str = "restores and proof are nonempty text";
const ARGUMENT: &str = "proof holds no NUL and is UTF-8 text a process takes as an argument";
const EXPECTED: &str = "expected is a list of profile names campaign can take";
const MISS: &str = "miss_cause is null or a cause with evidence";

/// Each field rule refuses the record with its sentence; a value one rule takes is refused by the next
/// rule only.
#[test]
fn each_field_rule_refuses_with_its_sentence() {
    let field = |name: &'static str, value: &'static str| {
        move |r: &Repository| r.write(JSON, replaced(name, value))
    };
    rows(&[
        (ID, &field("id", "\"beta\"")),
        (ID, &field("id", "1")),
        (ROW, &field("row", "0")),
        (ROW, &field("row", "true")),
        (ROW, &field("row", "1.0")),
        (ROW, &field("row", "\"1\"")),
        (
            FIX,
            &field("fix", "{\"pull_request\": 0, \"commit\": \"c\"}"),
        ),
        (
            FIX,
            &field("fix", "{\"pull_request\": 1, \"commit\": \" \"}"),
        ),
        (FIX, &field("fix", "{\"pull_request\": 1}")),
        (
            FIX,
            &field(
                "fix",
                "{\"pull_request\": 1, \"commit\": \"c\", \"by\": \"x\"}",
            ),
        ),
        (FIX, &field("fix", "[1, \"c\"]")),
        (FILES, &field("files", "[]")),
        (FILES, &field("files", "[\"src/lib.rs\", \"src/lib.rs\"]")),
        (FILES, &field("files", "[\"\\u3000\"]")),
        (FILES, &field("files", "\"src/lib.rs\"")),
        (TEXT, &field("restores", "\"\\u001c\\t\"")),
        (TEXT, &field("proof", "\"\"")),
        (TEXT, &field("restores", "null")),
        (ARGUMENT, &field("proof", "\"a\\u0000b\"")),
        (ARGUMENT, &field("proof", "\"\\udc80\"")),
        (EXPECTED, &field("expected", "[\"a/b\"]")),
        (EXPECTED, &field("expected", "[\"a,b\"]")),
        (EXPECTED, &field("expected", "[\"..\"]")),
        (EXPECTED, &field("expected", "[\"caf\\u00e9\"]")),
        (EXPECTED, &field("expected", "[\"smoke\", \"smoke\"]")),
        (
            MISS,
            &field(
                "miss_cause",
                "{\"cause\": \"weather\", \"evidence\": \"e\"}",
            ),
        ),
        (
            MISS,
            &field(
                "miss_cause",
                "{\"cause\": \"workload\", \"evidence\": \"\"}",
            ),
        ),
        (MISS, &field("miss_cause", "{\"cause\": \"workload\"}")),
        (MISS, &field("miss_cause", "false")),
    ]);
    let long = "x".repeat(243);
    let repository = Repository::new();
    repository.write(JSON, replaced("expected", &format!("[\"{long}\"]")));
    refused_with(&repository, &format!("alpha: {EXPECTED}"));
    let repository = Repository::new();
    repository.write(
        JSON,
        replaced("expected", &format!("[\"{}\"]", "x".repeat(242))),
    );
    refused_with(
        &repository,
        "the plant store differs from HEAD at verification/plants/alpha/plant.json; commit the plants first",
    );
}

/// Each of the four causes, with evidence, is a miss cause the record takes, and the plant keeps it in the
/// record's order.
#[test]
fn each_cause_with_evidence_is_taken() {
    for cause in ["environment", "workload", "ordering", "property"] {
        let repository = Repository::new();
        let value = format!("{{\"evidence\": \"the log\", \"cause\": \"{cause}\"}}");
        repository.write(JSON, replaced("miss_cause", &value));
        repository.commit();
        let Outcome::Run(inputs) = repository.prepare(&repository.call(&["--plant", "alpha"]))
        else {
            panic!("{cause} is taken");
        };
        let held = inputs.plants()[0].miss_cause().expect("a cause");
        let members: Vec<&(Text, Value)> = held.iter().collect();
        assert_eq!(
            members,
            [
                &(Text::from("evidence"), Value::String(Text::from("the log"))),
                &(Text::from("cause"), Value::String(Text::from(cause)))
            ]
        );
    }
}

/// Two rules broken at once give the first: the id's before the row's, the row's before the fix's.
#[test]
fn the_first_broken_rule_is_named() {
    let broken = |names: &[&str]| {
        let mut members = members("alpha", "src/lib.rs");
        for (name, value) in &mut members {
            if names.contains(&name.as_str()) {
                *value = if name == "id" { "\"other\"" } else { "0" }.to_owned();
            }
        }
        record(&members)
    };
    let (all, row_and_fix) = (broken(&["id", "row", "fix"]), broken(&["row", "fix"]));
    rows(&[
        (ID, &|r| r.write(JSON, &all)),
        (ROW, &|r| r.write(JSON, &row_and_fix)),
    ]);
}

/// A plant's name is its directory's name: it must not be the score's name, may hold at most 245 code
/// points, must equal the record's id and be printable ASCII without edge spaces. The bound counts code
/// points, so a name of 123 `é`, 246 bytes, passes it and is refused as no printable ASCII.
#[test]
fn the_directory_name_is_the_id() {
    let named = |name: &str| {
        let repository = Repository::new();
        let directory = format!("verification/plants/{name}");
        let mut members = members(name, "src/lib.rs");
        members[0].1 = format!("\"{}\"", name.replace('\t', "\\t"));
        repository.write(&format!("{directory}/plant.json"), record(&members));
        repository.write(&format!("{directory}/plant.patch"), patch("src/lib.rs"));
        let found = repository.refused(&repository.call(&[]));
        (found, directory)
    };
    let (found, _) = named("score.json");
    assert_eq!(
        found,
        "rejected: score.json: id is another name than score.json, the path of the run's score"
    );
    let long = "p".repeat(246);
    let (found, _) = named(&long);
    assert_eq!(
        found,
        format!(
            "rejected: {long}: id holds at most 245 bytes, so the proof's logs plant-<id>.out and \
             plant-<id>.err are file names"
        )
    );
    let (found, directory) = named(&"p".repeat(245));
    assert_eq!(
        found,
        format!(
            "rejected: the plant store differs from HEAD at {directory}/plant.json; commit the plants \
             first"
        )
    );
    let wide = "\u{e9}".repeat(123);
    let (found, _) = named(&wide);
    assert_eq!(found, format!("rejected: {wide}: {ID}"));
    for name in [" edge", "tab\there"] {
        let (found, _) = named(name);
        assert_eq!(found, format!("rejected: {name}: {ID}"));
    }
}

/// `numstat_error` is the first line of the error output of the host's `git apply --numstat` on `text`.
fn numstat_error(repository: &Repository, text: &str) -> String {
    let mut child = Command::new("git")
        .args(["apply", "--numstat"])
        .current_dir(&repository.top)
        .env_clear()
        .envs(repository.env())
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("git starts");
    std::io::Write::write_all(&mut child.stdin.take().expect("piped"), text.as_bytes())
        .expect("written");
    let output = child.wait_with_output().expect("git ends");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8");
    stderr
        .trim()
        .lines()
        .next()
        .expect("Git explains")
        .to_owned()
}

/// A patch Git cannot parse is refused with Git's first line of error; one that changes other paths than
/// its files, renames, copies, deletes, changes a mode or creates a file of another mode than 100644 is
/// refused with its paths or its summary line. A new file of mode 100644 changes contents alone.
#[test]
fn the_patch_changes_exactly_its_files_and_contents_alone() {
    for text in ["", "garbage\n"] {
        let repository = Repository::new();
        repository.write(PATCH, text);
        let first = numstat_error(&repository, text);
        refused_with(
            &repository,
            &format!("alpha: plant.patch is no patch: {first}"),
        );
    }
    let renamed = "diff --git a/src/lib.rs b/src/moved.rs\nsimilarity index 100%\n\
                   rename from src/lib.rs\nrename to src/moved.rs\n";
    let mode = format!(
        "diff --git a/src/lib.rs b/src/lib.rs\nold mode 100644\nnew mode 100755\n{}",
        &patch("src/lib.rs")["diff --git a/src/lib.rs b/src/lib.rs\n".len()..]
    );
    let created =
        "diff --git a/src/run.sh b/src/run.sh\nnew file mode 100755\nindex 0000000..e69de29\n";
    let copied = "diff --git a/src/lib.rs b/src/copy.rs\nsimilarity index 100%\n\
                  copy from src/lib.rs\ncopy to src/copy.rs\n";
    let deleted = format!(
        "diff --git a/src/lib.rs b/src/lib.rs\ndeleted file mode 100644\n--- a/src/lib.rs\n+++ /dev/null\n\
         @@ -1,3 +0,0 @@\n{}",
        LIB.lines()
            .map(|line| format!("-{line}\n"))
            .collect::<String>()
    );
    rows(&[
        (
            "plant.patch changes src/util.rs, and files names src/lib.rs",
            &|r| r.write(PATCH, patch("src/util.rs")),
        ),
        (
            "plant.patch does more than change file contents: rename src/{lib.rs => moved.rs} (100%)",
            &|r| {
                r.write(PATCH, renamed);
                r.write(JSON, replaced("files", "[\"src/moved.rs\"]"));
            },
        ),
        (
            "plant.patch does more than change file contents: mode change 100644 => 100755 src/lib.rs",
            &|r| r.write(PATCH, &mode),
        ),
        (
            "plant.patch does more than change file contents: create mode 100755 src/run.sh",
            &|r| {
                r.write(PATCH, created);
                r.write(JSON, replaced("files", "[\"src/run.sh\"]"));
            },
        ),
        (
            "plant.patch does more than change file contents: copy src/{lib.rs => copy.rs} (100%)",
            &|r| {
                r.write(PATCH, copied);
                r.write(JSON, replaced("files", "[\"src/copy.rs\"]"));
            },
        ),
        (
            "plant.patch does more than change file contents: delete mode 100644 src/lib.rs",
            &|r| r.write(PATCH, &deleted),
        ),
    ]);
    let repository = Repository::new();
    repository.write(
        PATCH,
        "diff --git a/src/new.rs b/src/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/src/new.rs\n\
         @@ -0,0 +1 @@\n+pub fn h() {}\n",
    );
    repository.write(JSON, replaced("files", "[\"src/new.rs\"]"));
    refused_with(
        &repository,
        "the plant store differs from HEAD at verification/plants/alpha/plant.json; commit the plants \
         first",
    );
}

/// A valid plant whose bytes differ from the head commit's, or which the head holds with another mode, is
/// refused as a store that differs from `HEAD` at that file.
#[test]
fn each_file_equals_the_regular_file_the_head_holds() {
    let differs = |file: &str| {
        format!(
            "the plant store differs from HEAD at verification/plants/alpha/{file}; commit the plants \
             first"
        )
    };
    let repository = Repository::new();
    repository.write(JSON, replaced("restores", "\"another sentence\""));
    refused_with(&repository, &differs("plant.json"));
    let repository = Repository::new();
    repository.write(PATCH, patch("src/lib.rs").replace("+    2", "+    3"));
    refused_with(&repository, &differs("plant.patch"));
    let repository = Repository::new();
    chmod(&repository.path(PATCH), 0o755);
    repository.commit();
    refused_with(&repository, &differs("plant.patch"));
}

/// With each edited file marked assume-unchanged, `git status` of the store prints nothing, so the
/// comparison of the bytes with the head's blob alone refuses the edit.
#[test]
fn the_bytes_are_compared_with_the_head_whatever_the_index_says() {
    let edits: [(&str, String); 2] = [
        (JSON, replaced("restores", "\"another sentence\"")),
        (PATCH, patch("src/lib.rs").replace("+    2", "+    3")),
    ];
    for (file, edited) in edits {
        let repository = Repository::new();
        repository.git(&["update-index", "--assume-unchanged", file]);
        repository.write(file, edited);
        let store = repository.git(&[
            "--no-optional-locks",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignored",
            "--",
            "verification/plants",
        ]);
        assert_eq!(store, "", "{file} is hidden from git status");
        refused_with(
            &repository,
            &format!("the plant store differs from HEAD at {file}; commit the plants first"),
        );
    }
}

/// Every plant of the store is checked, selected or not: a malformed `beta` refuses a run that selects
/// `alpha` alone.
#[test]
fn an_unselected_plant_is_checked_too() {
    let repository = Repository::new();
    write(
        &repository.path("verification/plants/beta/plant.json"),
        record(&members("beta", "src/util.rs")).replace("\"row\": 7", "\"row\": -7"),
    );
    assert_eq!(
        repository.refused(&repository.call(&["--plant", "alpha"])),
        format!("rejected: beta: {ROW}")
    );
}

/// `committed_run` commits the fixture's working tree and runs the checks with `args`, which must pass.
fn committed_run(repository: &Repository, args: &[&str]) -> Box<kestrike_tools::plants::Inputs> {
    repository.commit();
    match repository.prepare(&repository.call(args)) {
        Outcome::Run(inputs) => inputs,
        other => panic!("{args:?} runs, not {other:?}"),
    }
}

/// A list rule judges every item: a list with one good and one bad item is refused, and an empty
/// `expected` is taken and handed on empty.
#[test]
fn a_list_rule_judges_every_item() {
    rows(&[
        (FILES, &|r| {
            r.write(JSON, replaced("files", "[\"src/lib.rs\", \"\\u3000\"]"))
        }),
        (EXPECTED, &|r| {
            r.write(JSON, replaced("expected", "[\"smoke\", \"a/b\"]"))
        }),
        (EXPECTED, &|r| {
            r.write(JSON, replaced("expected", "[\"smoke\", \".\"]"))
        }),
        (EXPECTED, &|r| {
            r.write(JSON, replaced("expected", "[\"smoke\", \"a\\u007f\"]"))
        }),
    ]);
    let repository = Repository::new();
    repository.write(JSON, replaced("expected", "[]"));
    let inputs = committed_run(&repository, &["--plant", "alpha"]);
    assert!(inputs.plants()[0].expected().is_empty());
    let repository = Repository::new();
    repository.write(JSON, replaced("expected", "[\" a~b \"]"));
    let inputs = committed_run(&repository, &["--plant", "alpha"]);
    assert_eq!(inputs.plants()[0].expected(), [&Text::from(" a~b ")]);
}

/// The patch's paths and the record's files are compared as sorted lists in both directions, and the
/// refusal names each side sorted; a plant whose files are listed in another order than the patch's
/// keeps the record's order.
#[test]
fn a_plant_of_two_files_compares_sorted_paths() {
    let both = format!("{}{}", patch("src/lib.rs"), patch("src/util.rs"));
    rows(&[
        (
            "plant.patch changes src/lib.rs, src/util.rs, and files names src/lib.rs",
            &|r| r.write(PATCH, &both),
        ),
        (
            "plant.patch changes src/lib.rs, and files names src/lib.rs, src/util.rs",
            &|r| r.write(JSON, replaced("files", "[\"src/util.rs\", \"src/lib.rs\"]")),
        ),
    ]);
    let repository = Repository::new();
    repository.write(PATCH, &both);
    repository.write(JSON, replaced("files", "[\"src/util.rs\", \"src/lib.rs\"]"));
    let inputs = committed_run(&repository, &["--plant", "alpha"]);
    let [alpha] = inputs.plants() else {
        panic!("one plant is selected");
    };
    assert_eq!(
        alpha.files(),
        [&Text::from("src/util.rs"), &Text::from("src/lib.rs")]
    );
    assert_eq!(alpha.patch(), both.as_bytes());
}

/// The proof's rule takes any UTF-8 text without NUL: a proof outside ASCII and one longer than the
/// kernel's 131,072-byte bound on one argument both pass the checks.
#[test]
fn the_proof_rule_bounds_no_length_and_no_script() {
    for proof in ["suite::\u{e9}t\u{e9}".to_owned(), "x".repeat(1 << 17)] {
        let repository = Repository::new();
        repository.write(JSON, replaced("proof", &format!("\"{proof}\"")));
        let inputs = committed_run(&repository, &["--plant", "alpha"]);
        assert_eq!(inputs.plants()[0].proof(), &Text::from(proof.as_str()));
    }
}

/// `git apply --numstat` quotes a path outside ASCII, and the quoted spelling is compared with the
/// record's files, so a plant that changes `src/é.rs` is refused as changing another path.
#[test]
fn a_path_git_quotes_is_compared_as_quoted() {
    let repository = Repository::new();
    repository.git(&["config", "core.quotePath", "true"]);
    repository.write("src/\u{e9}.rs", LIB);
    repository.commit();
    repository.write("src/\u{e9}.rs", LIB.replace("    1", "    2"));
    let diff = repository.git(&["diff", "--", "src"]);
    repository.write("src/\u{e9}.rs", LIB);
    repository.write(PATCH, &diff);
    repository.write(JSON, replaced("files", "[\"src/\\u00e9.rs\"]"));
    repository.commit();
    refused_with(
        &repository,
        "alpha: plant.patch changes \"src/\\303\\251.rs\", and files names src/\u{e9}.rs",
    );
}

/// A `stat` of `plant.patch` that fails otherwise than as an absent file refuses the record with the
/// words `plant.json is unreadable` and the error; a link to a name past the length bound fails that way
/// for root too.
#[test]
fn a_failed_stat_of_the_patch_is_worded_as_the_record() {
    let repository = Repository::new();
    let patch_path = repository.path(PATCH);
    fs::remove_file(&patch_path).expect("removed");
    symlink("n".repeat(300), &patch_path).expect("linked");
    refused_with(
        &repository,
        &format!(
            "alpha: plant.json is unreadable: {}: File name too long (os error 36)",
            super::repository::shown(&patch_path)
        ),
    );
}

/// The repeated-member refusal holds the member's name as decoded, a lone surrogate included.
#[test]
fn a_repeated_member_is_named_as_decoded() {
    let repository = Repository::new();
    let mut members = members("alpha", "src/lib.rs");
    members.push(("\\ud800".to_owned(), "1".to_owned()));
    members.push(("\\ud800".to_owned(), "2".to_owned()));
    repository.write(JSON, record(&members));
    let Outcome::Rejected(reason) = repository.prepare(&repository.call(&[])) else {
        panic!("a repeated member is refused");
    };
    let mut expected = Text::from("alpha: plant.json is unreadable: repeated member ");
    expected.push_code_point(0xd800).expect("a code point");
    assert_eq!(reason, expected);
}
