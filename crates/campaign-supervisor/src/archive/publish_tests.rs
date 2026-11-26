//! Publication and verification of archives of a small dynamically linked
//! host executable, on the checkout's filesystem: what a published record
//! names, the identity cache, refusals before a use, changes during and
//! after a use, and kills at every step of a publication.

use std::fs::{self, File, FileTimes};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use super::verify::resolves_into;
use super::{Archive, Built, Error, Invalid, Unfinished, publish};
use crate::exit::Exit;
use crate::record::{Build, Digest, Native, Provenance, Text};
use crate::step::{Outcome, Step};
use crate::store::fixture::{Case, name, observed, processes, scripted};
use crate::store::{COPY_CHUNK, Name, Refusal, Store, Unreadable, View, open_host};

/// The executable every test archives: dynamically linked against the C
/// library alone.
const EXECUTABLE: &str = "/usr/bin/true";

fn text(value: &str) -> Text {
    Text::new(value).expect("the text is ASCII")
}

pub(crate) fn built() -> Built {
    built_from(Path::new(EXECUTABLE))
}

/// The fixture build of the executable at `path`, with its identity now.
pub(crate) fn built_from(path: &Path) -> Built {
    let digest = Digest::of(b"fixture");
    Built {
        executable: path.to_owned(),
        identity: open_host(path).expect("the executable opens").identity(),
        lock: b"version = 4\n".to_vec(),
        provenance: Provenance {
            cargo: text("cargo 1.0.0 (fake)"),
            command: text("test --locked"),
            dirty: true,
            environment: std::collections::BTreeMap::new(),
            native: Native {
                install_record: text("native"),
                install_record_sha256: digest,
                link_plan_sha256: digest,
                package: text("spdk-sys"),
            },
            revision: text(&"f".repeat(40)),
            target: text("x86_64-unknown-linux-gnu"),
            toolchain: text("rustc 1.0.0 (fake)"),
            untracked: 2,
        },
    }
}

/// A published archive at `case.root/archive`.
pub(super) fn published(case: &Case) -> PathBuf {
    let output = case.root.join("archive");
    publish(&output, &built()).expect("the archive publishes");
    output
}

fn sha256(path: &Path) -> Digest {
    Digest::of(&fs::read(path).expect("the file reads"))
}

/// How many reads `op` makes through the step seam.
fn reads<T>(op: impl FnOnce() -> T) -> (T, usize) {
    let (value, reached) = scripted([], op);
    let reads = reached.iter().filter(|&&step| step == Step::Read).count();
    (value.expect("nothing is scripted"), reads)
}

/// Makes `path` writable by its owner, as a tamperer would.
fn writable(path: &Path) {
    let mode = fs::metadata(path).expect("it exists").permissions().mode();
    fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o200)).expect("it is chmodded");
}

/// Flips the last byte of `path` in place and restores its modification
/// time, so only its status-change time tells the new version apart.
pub(super) fn flip_keeping_mtime(path: &Path) {
    let modified = fs::metadata(path)
        .expect("it exists")
        .modified()
        .expect("it has an mtime");
    writable(path);
    let mut bytes = fs::read(path).expect("it reads");
    *bytes.last_mut().expect("it holds bytes") ^= 1;
    fs::write(path, &bytes).expect("it is rewritten");
    let file = File::options().write(true).open(path).expect("it opens");
    file.set_times(FileTimes::new().set_modified(modified))
        .expect("the mtime is restored");
}

/// Replaces the archive's build record with `change` applied to it,
/// through the store, so the new record verifies under its own checksum.
fn reseal(output: &Path, change: impl FnOnce(&mut Build)) {
    let mut record = Archive::load(output).expect("it loads").record().clone();
    change(&mut record);
    fs::remove_file(output.join("build")).expect("the record is removed");
    let store = Store::open(output).expect("the archive opens as a store");
    store
        .create_record(store.root(), &name("build"), &record)
        .expect("the record is written");
}

/// Appends one byte to `entry` of the archive at `output`.
fn append(output: &Path, entry: &str) {
    let path = output.join(entry);
    writable(&path);
    let mut bytes = fs::read(&path).expect("it reads");
    bytes.push(0);
    fs::write(&path, bytes).expect("it is rewritten");
}

fn verified(output: &Path) -> Result<(), Invalid> {
    Archive::load(output)?.verify().map(drop)
}

/// A published archive holds the executable, the lockfile's exact bytes
/// and the libraries the interpreter resolves, read-only, beside a record
/// naming each digest, the interpreter, the machine and the provenance,
/// dirty state included; its `build` pin is the record's SHA-256, a view
/// lists the archive's entries without the store's own, and the approved
/// command runs the archived executable on the archived libraries, after
/// which the next verification is a cache hit.
#[test]
fn a_published_record_names_every_file_and_the_archive_verifies() {
    let _processes = processes();
    let case = Case::new();
    let output = published(&case);
    let mut archive = Archive::load(&output).expect("it loads");
    let record = archive.record().clone();
    assert_eq!(record.executable, sha256(Path::new(EXECUTABLE)));
    assert_eq!(
        fs::read(output.join("Cargo.lock")).expect("it reads"),
        b"version = 4\n"
    );
    assert_eq!(record.lock, Digest::of(b"version = 4\n"));
    let libc = record
        .libraries
        .get(&text("libc.so.6"))
        .expect("the C library is archived");
    assert_eq!(*libc, sha256(&output.join("lib/libc.so.6")));
    let loader = record.loader.clone().expect("the executable is dynamic");
    assert_eq!(loader.sha256, sha256(Path::new(loader.path.as_str())));
    assert_eq!(record.provenance, built().provenance);
    assert!(record.provenance.dirty);
    let mut names: Vec<String> = fs::read_dir(&output)
        .expect("it lists")
        .map(|entry| {
            entry
                .expect("it reads")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        [".staging", ".state", "Cargo.lock", "build", "lib", "worker"]
    );
    let view = View::open(&output).expect("it opens");
    let listed = view.list(view.root(), 8).expect("it lists");
    let listed: Vec<&str> = listed.iter().map(Name::as_str).collect();
    assert_eq!(listed, ["Cargo.lock", "build", "lib", "worker"]);
    for (entry, mode) in [
        ("worker", 0o500),
        ("Cargo.lock", 0o400),
        ("lib/libc.so.6", 0o400),
    ] {
        let bits = fs::metadata(output.join(entry))
            .expect("it exists")
            .permissions()
            .mode();
        assert_eq!(bits & 0o777, mode, "{entry}");
    }
    let pins = archive.pins();
    assert_eq!(
        pins.build.as_str(),
        sha256(&output.join("build")).to_string()
    );
    assert_eq!(pins.build.as_str(), archive.id().to_string());
    assert_eq!(pins.executable.as_str(), record.executable.to_string());
    assert_eq!(
        pins.platform.as_str(),
        format!("{}-linux", std::env::consts::ARCH)
    );
    assert_eq!(pins.toolchain.as_str(), "rustc 1.0.0 (fake)");
    let approved = archive.verify().expect("it verifies");
    let canonical = output.canonicalize().expect("it resolves");
    let mut command = approved.command();
    assert_eq!(command.get_program(), canonical.join("worker"));
    let envs: Vec<_> = command.get_envs().collect();
    let library_path = canonical.join("lib");
    assert!(envs.contains(&("LD_LIBRARY_PATH".as_ref(), Some(library_path.as_os_str()))));
    let ran = command.status().expect("the archived executable runs");
    assert!(ran.success(), "{ran}");
    approved.finish().expect("it verifies after the use");
    let (again, cached) = reads(|| archive.verify().map(drop));
    again.expect("it verifies again");
    assert_eq!(cached, 0, "the verification after a finish is a cache hit");
}

/// A second verification in one process is a cache hit that digests no
/// archive file; only the interpreter's listing runs again. A same-size rewrite of the record, the
/// executable, the lockfile or a library with its modification time
/// restored still changes the file's status-change time, and a new file in
/// the library directory changes the directory's; each breaks the cache,
/// so the full check refuses the archive.
#[test]
fn a_cache_hit_is_witnessed_and_a_restored_mtime_still_breaks_it() {
    let _processes = processes();
    for entry in [
        "build",
        "worker",
        "Cargo.lock",
        "lib/libc.so.6",
        "lib/libextra.so.1",
    ] {
        let case = Case::new();
        let output = published(&case);
        let mut archive = Archive::load(&output).expect("it loads");
        let (first, full) = reads(|| archive.verify().map(drop));
        first.expect("the first verification passes");
        assert!(full > 0, "the first verification reads the files");
        let (second, cached) = reads(|| archive.verify().map(drop));
        second.expect("the second verification passes");
        assert_eq!(cached, 0, "the second verification is a cache hit");
        let path = output.join(entry);
        if path.exists() {
            flip_keeping_mtime(&path);
        } else {
            fs::write(&path, b"x").expect("it is written");
        }
        let refused = archive.verify().map(drop);
        let expected = match entry {
            "lib/libextra.so.1" => matches!(refused, Err(Invalid::Libraries)),
            _ => {
                let name = Path::new(entry).file_name().expect("it has a name");
                matches!(&refused, Err(Invalid::Digest(digested)) if **digested == *name)
            }
        };
        assert!(expected, "{entry}: {refused:?}");
    }
}

/// Each alteration refuses the archive before a use: changed executable,
/// library or lockfile bytes, an extra, missing or symlinked library, a
/// missing or edited record, a record of another machine, interpreter or
/// interpreter digest, a record whose library the interpreter then
/// resolves outside the archive, a dynamic executable whose record names
/// no interpreter, an executable without its execute permission, and a
/// directory other users may read.
#[test]
fn every_altered_archive_is_refused_before_a_use() {
    let _processes = processes();
    type Change = fn(&Path);
    let cases: [(&str, Change); 15] = [
        ("executable", |output| append(output, "worker")),
        ("library", |output| append(output, "lib/libc.so.6")),
        ("lockfile", |output| append(output, "Cargo.lock")),
        ("extra library", |output| {
            fs::write(output.join("lib/libextra.so.1"), b"x").expect("it is written");
        }),
        ("missing library", |output| {
            fs::remove_file(output.join("lib/libc.so.6")).expect("it is removed");
        }),
        ("symlinked library", |output| {
            fs::remove_file(output.join("lib/libc.so.6")).expect("it is removed");
            symlink("/lib64/libc.so.6", output.join("lib/libc.so.6")).expect("it is linked");
        }),
        ("missing record", |output| {
            fs::remove_file(output.join("build")).expect("it is removed");
        }),
        ("edited record", |output| append(output, "build")),
        ("foreign machine", |output| {
            reseal(output, |record| record.machine = text("riscv64"))
        }),
        ("other interpreter", |output| {
            reseal(output, |record| {
                record.loader.as_mut().expect("dynamic").path = text(EXECUTABLE)
            });
        }),
        ("interpreter digest", |output| {
            reseal(output, |record| {
                record.loader.as_mut().expect("dynamic").sha256 = Digest::of(b"")
            });
        }),
        ("library resolved outside", |output| {
            reseal(output, |record| {
                record.libraries.clear();
            });
            fs::remove_file(output.join("lib/libc.so.6")).expect("it is removed");
        }),
        ("no interpreter", |output| {
            reseal(output, |record| record.loader = None);
        }),
        ("not executable", |output| {
            let worker = output.join("worker");
            fs::set_permissions(worker, fs::Permissions::from_mode(0o400)).expect("it is chmodded");
        }),
        ("shared directory", |output| {
            fs::set_permissions(output, fs::Permissions::from_mode(0o750)).expect("it is chmodded");
        }),
    ];
    for (label, change) in cases {
        let case = Case::new();
        let output = published(&case);
        change(&output);
        let refused = verified(&output).expect_err(label);
        let expected = match label {
            "executable" => matches!(&refused, Invalid::Digest(entry) if entry == "worker"),
            "library" => matches!(&refused, Invalid::Digest(entry) if entry == "libc.so.6"),
            "lockfile" => matches!(&refused, Invalid::Digest(entry) if entry == "Cargo.lock"),
            "extra library" => matches!(refused, Invalid::Libraries),
            "missing library" => {
                matches!(&refused, Invalid::Missing(entry) if entry == "libc.so.6")
            }
            "symlinked library" => {
                matches!(&refused, Invalid::Unreadable(entry, Unreadable::Symlink) if entry == "libc.so.6")
            }
            "missing record" => matches!(&refused, Invalid::Missing(entry) if entry == "build"),
            "edited record" => matches!(refused, Invalid::Record(_)),
            "foreign machine" => {
                matches!(&refused, Invalid::Machine(machine) if machine == "riscv64")
            }
            "other interpreter" | "no interpreter" => {
                matches!(&refused, Invalid::Elf(why) if why.contains("requests the interpreter"))
            }
            "not executable" => {
                matches!(&refused, Invalid::Elf(why) if why.contains("execute permission"))
            }
            "shared directory" => matches!(refused, Invalid::Refused(Refusal::Mode(0o750))),
            "interpreter digest" => matches!(refused, Invalid::Digest(_)),
            _ => matches!(refused, Invalid::Resolution(_)),
        };
        assert!(expected, "{label}: {refused:?}");
    }
}

/// An archive valid before a use that changes during it fails the check
/// after the use, exit 4, even when its bytes are restored; the failed
/// check leaves no cached approval, so the next use runs the full check
/// again.
#[test]
fn a_change_during_a_use_makes_the_use_incomplete_even_when_restored() {
    let _processes = processes();
    let case = Case::new();
    let output = published(&case);
    let library = output.join("lib/libc.so.6");
    let original = fs::read(&library).expect("it reads");
    let mut archive = Archive::load(&output).expect("it loads");
    let approved = archive.verify().expect("it verifies");
    writable(&library);
    fs::write(&library, b"changed").expect("it is rewritten");
    fs::write(&library, &original).expect("it is restored");
    let refused = approved.finish();
    assert!(matches!(refused, Err(Unfinished(Invalid::Changed))));
    let refused = Error::from(refused.expect_err("it is unfinished"));
    assert_eq!(Exit::Sim(refused.exit()).code(), 4);
    let (again, full) = reads(|| archive.verify().map(drop));
    again.expect("the restored archive verifies in full");
    assert!(full > 0);
    let approved = archive.verify().expect("it verifies");
    fs::write(&library, b"changed").expect("it is rewritten");
    let refused = approved.finish();
    assert!(
        matches!(&refused, Err(Unfinished(Invalid::Digest(name))) if name == "libc.so.6"),
        "{refused:?}"
    );
}

/// A file that changes after its digest is taken but before the check
/// ends is refused: the check's closing identities differ from its opening
/// ones.
#[test]
fn a_change_during_verification_is_refused() {
    let _processes = processes();
    let case = Case::new();
    let output = published(&case);
    let mut archive = Archive::load(&output).expect("it loads");
    let (_, reached) = scripted([], || archive.verify().map(drop));
    let last = reached
        .iter()
        .rposition(|&step| step == Step::Read)
        .expect("it reads");
    let mut archive = Archive::load(&output).expect("it loads");
    let lock = output.join("Cargo.lock");
    let mut index = 0;
    let refused = observed(
        move |_| {
            if index == last {
                writable(&lock);
                fs::write(&lock, b"changed").expect("it is rewritten");
            }
            index += 1;
        },
        || archive.verify().map(drop),
    );
    assert!(matches!(refused, Err(Invalid::Changed)), "{refused:?}");
}

/// A kill or an `EIO` at every boundary of a publication leaves either no
/// build record or an archive that verifies in full, never a record beside
/// a missing or partial file; a kill after the executable's copy and
/// before the libraries' leaves the copy without a record, and an error
/// once the output directory's creation has begun exits 4. A boundary is
/// the first step of each run of steps of one kind, reads and writes
/// counting as one kind, the first write of each such run, and every
/// sync, rename, directory creation, unlink and close, so each copy is
/// faulted at its first source read and at its first write. The
/// sweep ends with the build record's publication. Each faulted run
/// reaches its scheduled step, the same step the unfaulted run took
/// there, and a kill ends the publication.
#[test]
fn a_fault_at_any_publication_step_leaves_no_record_or_a_complete_archive() {
    let _processes = processes();
    let built = built();
    let dry = Case::new();
    let (done, reached) = scripted([], || publish(&dry.root.join("archive"), &built));
    done.expect("nothing is scripted")
        .expect("an unfaulted publication succeeds");
    let kind = |step: Step| {
        if step == Step::Read {
            Step::Write
        } else {
            step
        }
    };
    // The record's rename is the last; its directory sync and the store's
    // closing identity check follow it.
    let record = reached
        .iter()
        .rposition(|&step| step == Step::Rename)
        .expect("it renames");
    let end = record + 4;
    assert_eq!(
        reached[record + 1..end],
        [Step::Sync, Step::Stat, Step::Check]
    );
    let created = reached
        .iter()
        .position(|&step| step == Step::Mkdir)
        .expect("the output directory is created");
    let effect = |step: Step| {
        matches!(
            step,
            Step::Sync | Step::Rename | Step::Mkdir | Step::Unlink | Step::Close
        )
    };
    let boundary = |at: usize| {
        if at == 0 || effect(reached[at]) || kind(reached[at]) != kind(reached[at - 1]) {
            return true;
        }
        reached[at] == Step::Write
            && (0..at)
                .rev()
                .take_while(|&before| kind(reached[before]) == Step::Write)
                .all(|before| reached[before] != Step::Write)
    };
    let boundaries: Vec<usize> = (0..end).filter(|&at| boundary(at)).collect();
    assert!(
        boundaries.contains(&(end - 1)),
        "the closing Check is swept"
    );
    let syncs = reached[..end]
        .windows(2)
        .filter(|pair| pair[0] == pair[1] && effect(pair[0]))
        .count();
    assert!(syncs > 0, "a run of repeated effects is swept step by step");
    let mut without_record = 0;
    for &at in &boundaries {
        for outcome in [Outcome::Kill, Outcome::Errno(libc::EIO)] {
            let case = Case::new();
            let output = case.root.join("archive");
            let (done, faulted) = scripted([(at, outcome)], || publish(&output, &built));
            assert_eq!(faulted.get(at), Some(&reached[at]), "step {at}");
            match done {
                None => assert_eq!(outcome, Outcome::Kill, "step {at}"),
                Some(_) if outcome == Outcome::Kill => panic!("step {at}: the kill is survived"),
                Some(Ok(_)) => panic!("step {at}: {outcome:?} is reached"),
                Some(Err(error)) if at >= created => {
                    assert_eq!(
                        error.exit(),
                        crate::exit::Sim::Incomplete,
                        "step {at}: {error}"
                    );
                }
                Some(Err(_)) => {}
            }
            match Archive::load(&output) {
                Ok(mut archive) => archive
                    .verify()
                    .map(drop)
                    .expect("a recorded archive verifies"),
                Err(Invalid::Missing(entry)) => {
                    assert_eq!(entry, "build");
                    let copied = output.join("worker").exists();
                    if copied && !output.join("lib/libc.so.6").exists() {
                        without_record += 1;
                    }
                }
                Err(Invalid::Unreadable(..)) => assert!(!output.exists(), "step {at}"),
                Err(other) => panic!("step {at}: {other:?}"),
            }
        }
    }
    assert!(without_record > 0);
}

/// A loaded path the loader's search path splits or expands, or that holds
/// a byte outside printable ASCII, in its last component or an earlier
/// one, is refused, and so is a publication into one before anything is
/// written.
#[test]
fn unsearchable_paths_are_refused_at_load_and_publication() {
    let _processes = processes();
    let case = Case::new();
    let output = published(&case);
    for special in [":", ";", "$", "\u{7}", "\u{e9}"] {
        let moved = case.root.join(format!("bad{special}archive"));
        fs::rename(&output, &moved).expect("it moves");
        let refused = Archive::load(&moved).map(drop);
        assert!(matches!(refused, Err(Invalid::Path(_))), "{refused:?}");
        fs::rename(&moved, &output).expect("it moves back");
        let parent = case.root.join(format!("parent{special}"));
        fs::create_dir(&parent).expect("the parent is made");
        let nested = parent.join("archive");
        fs::rename(&output, &nested).expect("it moves");
        let refused = Archive::load(&nested).map(drop);
        assert!(matches!(refused, Err(Invalid::Path(_))), "{refused:?}");
        fs::rename(&nested, &output).expect("it moves back");
        for target in [&moved, &nested] {
            let refused = publish(target, &built()).expect_err("the path is refused");
            assert!(
                matches!(refused, Error::Invalid(Invalid::Path(_))),
                "{refused:?}"
            );
            assert!(!target.exists());
        }
        fs::remove_dir(&parent).expect("the parent is removed");
    }
}

/// A listing resolves into the archive only when it names exactly the
/// archive's libraries, each at its file in the library directory: a
/// library of the right name resolved elsewhere, an extra library and a
/// missing one are refused.
#[test]
fn a_resolution_must_name_each_library_at_its_archive_path() {
    let directory = Path::new("/archive/lib");
    let libraries = [
        (name("libc.so.6"), Digest::of(b"c")),
        (name("libm.so.6"), Digest::of(b"m")),
    ];
    let listing = |entries: &[(&str, &str)]| {
        entries
            .iter()
            .map(|&(name, path)| (name.to_owned(), path.to_owned()))
            .collect()
    };
    let exact = [
        ("libc.so.6", "/archive/lib/libc.so.6"),
        ("libm.so.6", "/archive/lib/libm.so.6"),
    ];
    resolves_into(listing(&exact), directory, &libraries).expect("the listing resolves inside");
    for refused in [
        &[
            ("libc.so.6", "/lib64/libc.so.6"),
            ("libm.so.6", "/archive/lib/libm.so.6"),
        ][..],
        &[exact[0], exact[1], ("libz.so.1", "/archive/lib/libz.so.1")],
        &[exact[0]],
    ] {
        let refused = resolves_into(listing(refused), directory, &libraries);
        assert!(
            matches!(refused, Err(Invalid::Resolution(_))),
            "{refused:?}"
        );
    }
}

/// An archive directory moved away during a use, with another archive at
/// its path, and then moved back fails the check after the use: the
/// directory's own identity changed with each rename.
#[test]
fn an_archive_swapped_during_a_use_and_restored_fails_the_finish() {
    let _processes = processes();
    let case = Case::new();
    let output = published(&case);
    let other = case.root.join("other");
    publish(&other, &built()).expect("it publishes");
    let mut archive = Archive::load(&output).expect("it loads");
    let approved = archive.verify().expect("it verifies");
    let aside = case.root.join("aside");
    fs::rename(&output, &aside).expect("it moves");
    fs::rename(&other, &output).expect("it moves");
    fs::rename(&output, &other).expect("it moves back");
    fs::rename(&aside, &output).expect("it moves back");
    let refused = approved.finish();
    assert!(
        matches!(refused, Err(Unfinished(Invalid::Changed))),
        "{refused:?}"
    );
}

/// A library altered after the build record's publication and before the
/// publication's closing verification makes the publication incomplete,
/// exit 4; the record stays, and the archive then fails its verification.
#[test]
fn a_failed_closing_verification_makes_the_publication_incomplete() {
    let _processes = processes();
    let built = built();
    let dry = Case::new();
    let (_, reached) = scripted([], || publish(&dry.root.join("archive"), &built));
    let record = reached
        .iter()
        .rposition(|&step| step == Step::Rename)
        .expect("it renames");
    let case = Case::new();
    let output = case.root.join("archive");
    let archived = output.clone();
    let mut index = 0;
    let failed = observed(
        move |_| {
            if index == record + 3 {
                append(&archived, "lib/libc.so.6");
            }
            index += 1;
        },
        || publish(&output, &built),
    )
    .expect_err("the closing verification fails");
    assert!(matches!(failed, Error::Incomplete(_)), "{failed}");
    assert_eq!(Exit::Sim(failed.exit()).code(), 4);
    assert!(output.join("build").exists());
    let refused = verified(&output);
    assert!(
        matches!(&refused, Err(Invalid::Digest(entry)) if entry == "libc.so.6"),
        "{refused:?}"
    );
}

/// An archive directory replaced at its path after it was loaded fails the
/// next verification, cached or not, since a use runs the files the path
/// names.
#[test]
fn an_archive_replaced_at_its_path_is_refused() {
    let _processes = processes();
    let case = Case::new();
    let output = published(&case);
    let other = case.root.join("other");
    publish(&other, &built()).expect("it publishes");
    let mut archive = Archive::load(&output).expect("it loads");
    archive
        .verify()
        .expect("it verifies")
        .finish()
        .expect("it verifies after the use");
    fs::rename(&output, case.root.join("old")).expect("it moves");
    fs::rename(&other, &output).expect("it moves");
    assert!(matches!(archive.verify().map(drop), Err(Invalid::Changed)));
    Archive::load(&output)
        .expect("it loads")
        .verify()
        .map(drop)
        .expect("the new one verifies");
}

/// A source that changes or disappears after it is opened and before its
/// copy ends makes the publication incomplete, exit 4, and leaves no build
/// record: at the first write, the state marker's, before the copy reads
/// it, so the copy holds the new bytes, and at the executable copy's
/// last write, so the copy holds the original ones. So does an
/// executable replaced or removed between its build and the publication.
#[test]
fn a_source_changed_during_its_copy_leaves_no_record() {
    let _processes = processes();
    let original = fs::read(EXECUTABLE).expect("it reads");
    let last = 1 + original.len().div_ceil(COPY_CHUNK);
    for (at, removed) in [(1, false), (1, true), (last, false), (last, true)] {
        let case = Case::new();
        let source = case.root.join("source");
        fs::copy(EXECUTABLE, &source).expect("it is copied");
        let built = built_from(&source);
        let output = case.root.join("archive");
        let mut writes = 0;
        let failed = observed(
            move |step| {
                writes += usize::from(step == Step::Write);
                if step == Step::Write && writes == at {
                    if removed {
                        fs::remove_file(&source).expect("it is removed");
                    } else {
                        fs::write(&source, b"changed").expect("it is rewritten");
                    }
                }
            },
            || publish(&output, &built),
        )
        .expect_err("the publication is incomplete");
        assert!(matches!(failed, Error::Incomplete(_)), "{failed}");
        assert_eq!(Exit::Sim(failed.exit()).code(), 4);
        if removed {
            assert!(
                failed.to_string().contains("unreadable after its copy"),
                "{failed}"
            );
        }
        let refused = Archive::load(&output).map(drop);
        assert!(
            matches!(&refused, Err(Invalid::Missing(entry)) if entry == "build"),
            "{refused:?}"
        );
        if !removed {
            let copied = fs::read(output.join("worker")).expect("the copy is published");
            let expected: &[u8] = if at == 1 { b"changed" } else { &original };
            assert_eq!(copied, expected, "write {at}");
        }
    }
    for removed in [false, true] {
        let case = Case::new();
        let source = case.root.join("source");
        fs::copy(EXECUTABLE, &source).expect("it is copied");
        let built = built_from(&source);
        if removed {
            fs::remove_file(&source).expect("it is removed");
        } else {
            fs::rename(&source, case.root.join("aside")).expect("it moves aside");
            fs::copy(EXECUTABLE, &source).expect("it is replaced");
        }
        let output = case.root.join("archive");
        let failed = publish(&output, &built).expect_err("the publication is incomplete");
        assert!(matches!(failed, Error::Incomplete(_)), "{failed}");
        assert!(!output.exists(), "nothing is written");
    }
}

/// A new output directory the store refuses, here for the mode a
/// narrowing umask gives it, exits 2 and is removed; a removal that fails
/// exits 4 and leaves the directory.
#[test]
fn a_refused_output_directory_is_removed() {
    let _processes = processes();
    let case = Case::new();
    let output = case.root.join("archive");
    let built = built();
    let (refused, failed) = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                crate::sys::private_fs(0o277).expect("the thread gets its own umask");
                let (refused, reached) = scripted([], || publish(&output, &built).map(drop));
                let removal = reached
                    .iter()
                    .rposition(|&step| step == Step::Unlink)
                    .expect("the refused directory is removed");
                let faulted = [(removal, Outcome::Errno(libc::EIO))];
                let (failed, _) = scripted(faulted, || publish(&output, &built).map(drop));
                (refused, failed)
            })
            .join()
            .expect("the publication thread finishes")
    });
    let refused = refused
        .expect("nothing is scripted")
        .expect_err("the store refuses the directory");
    assert!(
        matches!(refused, Error::Invalid(Invalid::Refused(_))),
        "{refused}"
    );
    assert_eq!(Exit::Sim(refused.exit()).code(), 2);
    let failed = failed
        .expect("an errno ends no thread")
        .expect_err("the removal fails");
    assert!(matches!(failed, Error::Incomplete(_)), "{failed}");
    assert_eq!(Exit::Sim(failed.exit()).code(), 4);
    assert!(output.exists(), "a failed removal leaves the directory");
}

/// An archive directory whose mode widens after its load fails the next
/// verification, cached or not, and a directory on another filesystem
/// type than ext4 or xfs is refused at its load.
#[test]
fn a_widened_or_foreign_directory_is_refused() {
    let _processes = processes();
    let case = Case::new();
    let output = published(&case);
    let mut archive = Archive::load(&output).expect("it loads");
    archive.verify().map(drop).expect("it verifies");
    fs::set_permissions(&output, fs::Permissions::from_mode(0o750)).expect("it is chmodded");
    let refused = archive.verify().map(drop);
    assert!(
        matches!(refused, Err(Invalid::Refused(Refusal::Mode(0o750)))),
        "{refused:?}"
    );
    let refused = Archive::load(Path::new("/proc")).map(drop);
    assert!(
        matches!(&refused, Err(Invalid::Refused(Refusal::Filesystem(kind))) if kind == "proc"),
        "{refused:?}"
    );
}

#[test]
fn shared_ancestors_refuse_pathname_uses() {
    let _processes = processes();
    let case = Case::new();
    let output = published(&case);
    fs::set_permissions(&case.root, fs::Permissions::from_mode(0o777)).expect("mode changes");
    let refused = Archive::load(&output).expect_err("the ancestor is shared");
    assert!(
        matches!(refused, Invalid::Refused(Refusal::Ancestor(_))),
        "{refused}"
    );
    fs::set_permissions(&case.root, fs::Permissions::from_mode(0o700)).expect("mode restores");
    let mut archive = Archive::load(&output).expect("the private ancestor is accepted");
    archive.verify().map(drop).expect("the archive verifies");
    fs::set_permissions(&case.root, fs::Permissions::from_mode(0o777)).expect("mode changes");
    let refused = archive
        .verify()
        .map(drop)
        .expect_err("the ancestor became shared");
    assert!(
        matches!(refused, Invalid::Refused(Refusal::Ancestor(_))),
        "{refused}"
    );
    fs::set_permissions(&case.root, fs::Permissions::from_mode(0o700)).expect("mode restores");
}

/// Verification refuses a symlink ancestor even when it resolves to the
/// loaded directory, because replacing the symlink can redirect the
/// worker's path between verification and process spawn.
#[test]
fn an_ancestor_replaced_by_a_symlink_refuses_pathname_uses() {
    let _processes = processes();
    let case = Case::new();
    let root = case.root.canonicalize().expect("the case root resolves");
    let parent = root.join("parent");
    fs::create_dir(&parent).expect("the parent is made");
    let output = parent.join("archive");
    publish(&output, &built()).expect("the archive publishes");
    let mut archive = Archive::load(&output).expect("it loads");
    archive.verify().map(drop).expect("the archive verifies");
    let moved = root.join("moved");
    fs::rename(&parent, &moved).expect("the parent moves");
    symlink(&moved, &parent).expect("a symlink takes the parent's place");
    let refused = archive
        .verify()
        .map(drop)
        .expect_err("an ancestor is a symlink");
    assert!(
        matches!(&refused, Invalid::Refused(Refusal::Ancestor(path)) if Path::new(path) == parent),
        "{refused}"
    );
}

#[test]
fn output_creation_clears_setgid_and_retries_each_call_separately() {
    use std::os::unix::fs::MetadataExt;
    let case = Case::new();
    let parent = case.root.join("parent");
    fs::create_dir(&parent).expect("parent created");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o2700)).expect("setgid set");
    let output = parent.join("archive");
    let (_, trace) = scripted([], || crate::store::create_dir(&output).expect("created"));
    assert_eq!(
        trace,
        [
            Step::Mkdir,
            Step::Open,
            Step::Stat,
            Step::Chmod,
            Step::Chmod
        ]
    );
    assert_eq!(
        fs::metadata(&output).expect("mode reads").mode() & 0o7777,
        0o700
    );
    crate::store::remove_dir(&output).expect("removed");
    for index in 1..trace.len() {
        let (created, trace) = scripted([(index, Outcome::Errno(libc::EINTR))], || {
            crate::store::create_dir(&output)
        });
        created
            .expect("script returns")
            .expect("interruption retries");
        assert_eq!(trace.iter().filter(|&&step| step == Step::Mkdir).count(), 1);
        assert_eq!(
            fs::metadata(&output).expect("mode reads").mode() & 0o7777,
            0o700
        );
        crate::store::remove_dir(&output).expect("removed");
    }
    let victim = parent.join("victim");
    fs::write(&victim, "private").expect("victim created");
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).expect("mode set");
    let aside = parent.join("aside");
    let swapped = output.clone();
    let moved = aside.clone();
    let target = victim.clone();
    let created = observed(
        move |step| {
            if step == Step::Stat {
                fs::rename(&swapped, &moved).expect("new directory moves");
                symlink(&target, &swapped).expect("entry substituted");
            }
        },
        || crate::store::create_dir(&output),
    );
    created.expect("handle-bound chmod succeeds");
    assert_eq!(
        fs::metadata(&victim).expect("victim exists").mode() & 0o7777,
        0o600
    );
    assert_eq!(
        fs::metadata(&aside).expect("original exists").mode() & 0o7777,
        0o700
    );
}

#[test]
fn relative_directory_removal_syncs_its_pinned_parent() {
    let case = Case::new();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                crate::sys::private_fs(0o022).expect("private working directory");
                std::env::set_current_dir(&case.root).expect("working directory changes");
                fs::create_dir("archive").expect("directory created");
                let (removed, trace) =
                    scripted([], || crate::store::remove_dir(Path::new("archive")));
                removed.expect("script returns").expect("removed");
                assert_eq!(trace, [Step::Open, Step::Unlink, Step::Sync]);
                assert!(!Path::new("archive").exists());
                for index in [0, 2] {
                    fs::create_dir("archive").expect("directory created");
                    let (removed, _) = scripted([(index, Outcome::Errno(libc::EIO))], || {
                        crate::store::remove_dir(Path::new("archive"))
                    });
                    assert_eq!(
                        removed
                            .expect("script returns")
                            .expect_err("step fails")
                            .raw_os_error(),
                        Some(libc::EIO)
                    );
                    assert_eq!(Path::new("archive").exists(), index == 0);
                    if index == 0 {
                        fs::remove_dir("archive").expect("cleanup");
                    }
                }
            })
            .join()
            .expect("thread completes")
    });
}

#[test]
fn cleanup_faults_keep_the_refusal_and_report_the_removed_state() {
    let _processes = processes();
    let case = Case::new();
    let output = case.root.join("archive");
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                crate::sys::private_fs(0o277).expect("private umask");
                let (result, trace) = scripted([], || publish(&output, &built()).map(drop));
                assert_eq!(
                    result.expect("script returns").expect_err("refused").exit(),
                    crate::exit::Sim::Rejected
                );
                let end = trace.len() - 3;
                assert_eq!(&trace[end..], [Step::Open, Step::Unlink, Step::Sync]);
                for index in end..trace.len() {
                    let (failed, _) = scripted([(index, Outcome::Errno(libc::EIO))], || {
                        publish(&output, &built()).map(drop)
                    });
                    let failed = failed.expect("script returns").expect_err("cleanup fails");
                    assert_eq!(failed.exit(), crate::exit::Sim::Incomplete);
                    assert!(
                        failed.to_string().contains("output was refused"),
                        "{failed}"
                    );
                    assert!(failed.to_string().contains("Mode(320)"), "{failed}");
                    assert_eq!(output.exists(), index != end + 2);
                    if output.exists() {
                        fs::remove_dir(&output).expect("cleanup");
                    }
                }
            })
            .join()
            .expect("thread finishes")
    });
}

#[test]
fn an_initial_elf_read_failure_is_incomplete() {
    let _processes = processes();
    let case = Case::new();
    let output = case.root.join("archive");
    let built = built();
    let (result, trace) = scripted([], || publish(&output, &built));
    result
        .expect("script returns")
        .expect("publication succeeds");
    fs::remove_dir_all(&output).expect("fixture removed");
    let index = trace
        .iter()
        .position(|&step| step == Step::Read)
        .expect("ELF read witnessed");
    let (result, _) = scripted([(index, Outcome::Errno(libc::EIO))], || {
        publish(&output, &built)
    });
    let failed = result.expect("script returns").expect_err("read fails");
    assert_eq!(failed.exit(), crate::exit::Sim::Incomplete);
    assert!(failed.to_string().contains("failed its read"), "{failed}");
    assert!(!output.exists());
}

#[test]
fn post_creation_failures_name_the_completed_stage() {
    let case = Case::new();
    for (index, reason) in [
        (1, "opening"),
        (2, "reading its mode"),
        (3, "setting its mode"),
    ] {
        let output = case.root.join(format!("creation-{index}"));
        let (result, _) = scripted([(index, Outcome::Errno(libc::EIO))], || {
            crate::store::create_dir(&output)
        });
        let error = result
            .expect("script returns")
            .expect_err("post-creation step fails");
        assert!(error.to_string().contains("directory created"), "{error}");
        assert!(error.to_string().contains(reason), "{error}");
        assert!(output.exists());
    }
}

#[test]
fn loading_an_archive_barriers_its_build_record_and_directory() {
    let _processes = processes();
    let case = Case::new();
    let path = published(&case);
    let (loaded, reached) = scripted([], || Archive::load(&path));
    loaded.expect("script").expect("archive");
    let syncs: Vec<_> = reached
        .iter()
        .enumerate()
        .filter_map(|(at, step)| (*step == Step::Sync).then_some(at))
        .collect();
    assert_eq!(syncs.len(), 2);
    for at in syncs {
        let (loaded, _) = scripted([(at, Outcome::Errno(libc::EIO))], || Archive::load(&path));
        assert!(matches!(loaded, Some(Err(Invalid::Io(_)))), "{loaded:?}");
    }
}

#[test]
fn a_mode_change_during_publication_is_incomplete() {
    let _processes = processes();
    let built = built();
    let dry = Case::new();
    let (_, reached) = scripted([], || publish(&dry.root.join("archive"), &built));
    let write = reached
        .iter()
        .rposition(|step| *step == Step::Write)
        .expect("build record write");
    let case = Case::new();
    let output = case.root.join("archive");
    let root = output.clone();
    let mut index = 0;
    let result = observed(
        move |_| {
            if index == write {
                fs::set_permissions(&root, fs::Permissions::from_mode(0o750))
                    .expect("changed mode");
            }
            index += 1;
        },
        || publish(&output, &built),
    );
    let error = result.expect_err("changed archive mode");
    assert!(
        matches!(
            error,
            Error::Store(crate::store::Error::Refused(Refusal::Mode(0o750)))
        ),
        "{error:?}"
    );
    assert_eq!(error.exit(), crate::exit::Sim::Incomplete);
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).expect("private mode");
}

/// An output path whose given prefix holds a symlink is refused before
/// the parent is resolved, so a link placed in a shared directory cannot
/// route a new archive into its target, where the resolved path's
/// ancestors would pass.
#[test]
fn a_symlink_in_the_output_prefix_is_refused() {
    let case = Case::new();
    let elsewhere = case.root.join("elsewhere");
    fs::create_dir(&elsewhere).expect("the target");
    let shared = case.root.join("shared");
    fs::create_dir(&shared).expect("the shared directory");
    symlink(&elsewhere, shared.join("link")).expect("the link");
    let refused =
        super::vacant(&shared.join("link/out")).expect_err("the linked prefix is refused");
    assert!(
        matches!(&refused, Invalid::Refused(Refusal::Ancestor(path)) if Path::new(path) == shared.join("link")),
        "{refused}"
    );
    assert!(!elsewhere.join("out").exists());
}

/// An output path beneath a regular file is a refused input, exit 2: the
/// given-prefix check reports the component's status failure the way the
/// parent resolution does, so the host-fault rule decides the class.
#[test]
fn an_output_prefix_under_a_file_is_rejected() {
    let case = Case::new();
    let file = case.root.join("file");
    fs::write(&file, b"bytes").expect("the file");
    let refused = super::vacant(&file.join("out")).expect_err("a file is no ancestor");
    assert!(
        matches!(&refused, Invalid::Unreadable(path, Unreadable::Io(_)) if Path::new(path) == file.join("out")),
        "{refused}"
    );
    assert_eq!(refused.exit(false), crate::exit::Sim::Rejected);
}
