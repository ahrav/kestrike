//! The store's checks: its place, its listing, the plant directories it holds, the selection, and the
//! store against the head commit. Each refusal leaves no path made and `git status` as it was.

use std::fs;
use std::os::unix::fs::symlink;

use kestrike_tools::plants::Outcome;
use kestrike_tools::text::Text;

use super::repository::{Repository, chmod, is_root, members, patch, record, shown};

fn differs(paths: &str) -> String {
    format!("rejected: the plant store differs from HEAD at {paths}; commit the plants first")
}

/// `verification` or `verification/plants` as a link is refused, the parent first; a store that is no
/// directory is refused with its path.
#[test]
fn the_store_and_its_parent_are_directories_of_the_checkout() {
    let repository = Repository::new();
    let parent = repository.path("verification");
    let moved = repository.scratch.join("verification");
    fs::rename(&parent, &moved).expect("moved");
    symlink(&moved, &parent).expect("linked");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        format!(
            "rejected: {} is a link; the plant store must be a directory of the checkout",
            shown(&parent)
        )
    );
    let repository = Repository::new();
    let store_link = repository.path("verification/plants");
    let moved = repository.scratch.join("plants");
    fs::rename(&store_link, &moved).expect("moved");
    symlink(&moved, &store_link).expect("linked");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        format!(
            "rejected: {} is a link; the plant store must be a directory of the checkout",
            shown(&store_link)
        )
    );
    let repository = Repository::new();
    fs::remove_dir_all(repository.path("verification/plants")).expect("removed");
    repository.write("verification/plants", "a file\n");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        format!(
            "rejected: {} is no directory",
            shown(&repository.path("verification/plants"))
        )
    );
}

/// A store the user cannot list is refused with the operating system's error.
#[test]
fn an_unreadable_store_is_refused() {
    if is_root() {
        return;
    }
    let repository = Repository::new();
    let store = repository.path("verification/plants");
    chmod(&store, 0o300);
    assert_eq!(
        repository.refused(&repository.call(&[])),
        format!(
            "rejected: the plant store cannot be read: {}: Permission denied (os error 13)",
            shown(&store)
        )
    );
}

/// A store whose entries are files alone holds no plant; a file beside the plants is no plant and is
/// passed over, so the store then differs from the head at it.
#[test]
fn a_file_of_the_store_is_no_plant() {
    let repository = Repository::new();
    for id in ["alpha", "beta"] {
        fs::remove_dir_all(repository.path(&format!("verification/plants/{id}"))).expect("removed");
    }
    repository.write("verification/plants/README", "notes\n");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        format!(
            "rejected: {} holds no plant",
            shown(&repository.path("verification/plants"))
        )
    );
    let repository = Repository::new();
    repository.write("verification/plants/README", "notes\n");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        differs("verification/plants/README")
    );
}

/// A link to a directory is a plant: its files are read through it, and the store then differs from the
/// head at the link.
#[test]
fn a_link_to_a_directory_is_a_plant() {
    let repository = Repository::new();
    let alpha = repository.path("verification/plants/alpha");
    let moved = repository.scratch.join("alpha");
    fs::rename(&alpha, &moved).expect("moved");
    symlink(&moved, &alpha).expect("linked");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        differs(
            "verification/plants/alpha/plant.json, verification/plants/alpha/plant.patch, \
             verification/plants/alpha"
        )
    );
    let repository = Repository::new();
    let alpha = repository.path("verification/plants/alpha");
    let moved = repository.scratch.join("alpha");
    fs::rename(&alpha, &moved).expect("moved");
    fs::write(moved.join("plant.json"), "{}").expect("written");
    symlink(&moved, &alpha).expect("linked");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        "rejected: alpha: plant.json holds exactly the fields id, row, fix, files, restores, proof, \
         expected, miss_cause"
    );
}

/// Every unknown `--plant` is named in command-line order, before the store is compared with the head.
#[test]
fn an_unknown_plant_is_named_before_a_changed_store() {
    let repository = Repository::new();
    repository.write("verification/plants/notes.txt", "notes\n");
    assert_eq!(
        repository.refused(&repository.call(&[
            "--plant",
            "zeta",
            "--plant",
            "alpha",
            "--plant=omega"
        ])),
        "rejected: no plant named zeta, omega"
    );
}

/// Untracked and ignored files of the store are differences from the head, each by its path; the score
/// and a staging file of one are passed over, so the run goes on.
#[test]
fn the_store_differs_from_head_at_untracked_and_ignored_paths_but_the_score() {
    let repository = Repository::new();
    repository.write(".gitignore", "Cargo.lock\n*.log\n");
    repository.commit();
    repository.write("verification/plants/alpha/run.log", "log\n");
    repository.write("verification/plants/new.txt", "new\n");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        differs("verification/plants/new.txt, verification/plants/alpha/run.log")
    );
    let repository = Repository::new();
    repository.write("verification/plants/score.json", "{}\n");
    repository.write("verification/plants/.score.json.abcd1234", "{}\n");
    repository.write("verification/plants/alpha/..score.json", "{}\n");
    let Outcome::Run(inputs) = repository.prepare(&repository.call(&[])) else {
        panic!("the score is passed over");
    };
    assert_eq!(
        inputs.score(),
        repository.path("verification/plants/score.json")
    );
    let repository = Repository::new();
    repository.write("verification/plants/notes-score.json", "{}\n");
    repository.write("verification/plants/score.jso", "{}\n");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        differs("verification/plants/notes-score.json, verification/plants/score.jso")
    );
}

/// A staged rename of a tracked file of the store to `score.json` shows in `git status` as one rename row
/// whose file name is the score's, so the removal of its source is passed over and the run goes on.
#[test]
fn a_rename_to_the_score_hides_its_source() {
    let repository = Repository::new();
    repository.write("verification/plants/notes.txt", "notes\n");
    repository.commit();
    repository.git(&[
        "mv",
        "verification/plants/notes.txt",
        "verification/plants/score.json",
    ]);
    let status = repository.git(&["status", "--porcelain", "--", "verification/plants"]);
    assert_eq!(
        status,
        "R  verification/plants/notes.txt -> verification/plants/score.json\n"
    );
    let Outcome::Run(inputs) = repository.prepare(&repository.call(&[])) else {
        panic!("the rename is passed over");
    };
    assert_eq!(inputs.plants().len(), 2);
}

/// A plant directory the head holds and the store lacks is a difference, though `git status` reports
/// none when the index skips its files.
#[test]
fn a_plant_the_head_holds_and_the_store_lacks_differs() {
    let repository = Repository::new();
    repository.git(&[
        "update-index",
        "--skip-worktree",
        "verification/plants/beta/plant.json",
        "verification/plants/beta/plant.patch",
    ]);
    fs::remove_dir_all(repository.path("verification/plants/beta")).expect("removed");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        differs("verification/plants/beta")
    );
}

/// Plants are taken in the byte order of their names, and `--plant` selects among them without changing
/// that order.
#[test]
fn plants_are_taken_in_byte_order() {
    let repository = Repository::new();
    for (id, file) in [("Zulu", "src/lib.rs"), ("a-1", "src/util.rs")] {
        repository.write(
            &format!("verification/plants/{id}/plant.json"),
            record(&members(id, file)),
        );
        repository.write(
            &format!("verification/plants/{id}/plant.patch"),
            patch(file),
        );
    }
    repository.commit();
    let Outcome::Run(inputs) =
        repository.prepare(&repository.call(&["--plant", "beta", "--plant", "Zulu"]))
    else {
        panic!("the selection runs");
    };
    let ids: Vec<&Text> = inputs.plants().iter().map(|plant| plant.id()).collect();
    assert_eq!(ids, [&Text::from("Zulu"), &Text::from("beta")]);
    let Outcome::Run(inputs) = repository.prepare(&repository.call(&[])) else {
        panic!("the store runs");
    };
    let ids: Vec<String> = inputs
        .plants()
        .iter()
        .map(|plant| plant.id().to_string())
        .collect();
    assert_eq!(ids, ["Zulu", "a-1", "alpha", "beta"]);
}

/// With the parent and the store both links, the parent is named; both are tested before either is
/// refused, so a store whose `lstat` fails beneath a linked parent is a failure outside a plant.
#[test]
fn both_links_are_tested_before_the_parent_is_named() {
    let repository = Repository::new();
    let (parent, store) = (
        repository.path("verification"),
        repository.path("verification/plants"),
    );
    let kept = repository.scratch.join("kept-plants");
    fs::rename(&store, &kept).expect("moved");
    symlink(&kept, &store).expect("linked");
    let moved = repository.scratch.join("verification");
    fs::rename(&parent, &moved).expect("moved");
    symlink(&moved, &parent).expect("linked");
    assert_eq!(
        repository.refused(&repository.call(&[])),
        format!(
            "rejected: {} is a link; the plant store must be a directory of the checkout",
            shown(&parent)
        )
    );
    if is_root() {
        return;
    }
    chmod(&moved, 0o000);
    assert_eq!(
        repository.refused(&repository.call(&[])),
        format!(
            "failed: the plant store cannot be tested for a link: {}: Permission denied (os error 13)",
            shown(&store)
        )
    );
}
