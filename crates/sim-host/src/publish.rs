//! `sim-host publish`: the loop that builds each new head of `origin/main`
//! once and stores it. A head's objects are written create-once in the
//! order archive, binary, commit record, and `current.json` is replaced
//! last, so every commit record names objects already stored. A head that
//! is refused for its content is skipped while `origin/main` names it.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::build::{self, Commit};
use crate::capture::{self, Halt};
use crate::cli::Publish;
use crate::store::{Bucket, Error, LONG, SHORT};
use crate::{file, signal};

const GIT_WAIT: Duration = Duration::from_secs(600);
const BUILD_WAIT: Duration = Duration::from_secs(4 * 3600);
const OUTPUT: u64 = 16 << 20;
const HOST_FAULT: i32 = 4;
const INTERRUPTED: i32 = 5;

struct Paths {
    checkout: PathBuf,
    state: PathBuf,
}

pub fn publish(options: &Publish) -> u8 {
    if let Err(error) = signal::install() {
        eprintln!("sim-host publish: signal handlers: {error}");
        return 2;
    }
    let resolved = std::path::absolute(&options.checkout)
        .and_then(|checkout| Ok((checkout, std::path::absolute(&options.state)?)));
    let paths = match resolved {
        Ok((checkout, state)) => Paths { checkout, state },
        Err(error) => {
            eprintln!("sim-host publish: the working directory: {error}");
            return 2;
        }
    };
    if let Err(error) = file::private_dir(&paths.state) {
        eprintln!("sim-host publish: {}: {error}", paths.state.display());
        return 2;
    }
    let lock_path = paths.state.join("publisher.lock");
    let _lock = match file::lock(&lock_path) {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            eprintln!(
                "sim-host publish: another publisher holds {}",
                paths.state.display()
            );
            return 2;
        }
        Err(error) => {
            eprintln!("sim-host publish: {}: {error}", lock_path.display());
            return 2;
        }
    };
    let bucket = Bucket::new(&options.bucket);
    let mut skipped = None;
    while !signal::stopping() {
        match once(&paths, &bucket, &mut skipped) {
            Ok(report) => println!("{report}"),
            Err(error) => eprintln!("sim-host publish: {error}"),
        }
        signal::wait(options.interval);
    }
    0
}

enum Failure {
    Refused(String),
    Retry(String),
}

fn run(
    program: &Path,
    checkout: &Path,
    args: &[&str],
    env: &[(&str, &str)],
    wait: Duration,
) -> Result<String, Failure> {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(checkout)
        .envs(env.iter().copied());
    let name = program.display().to_string();
    let output =
        capture::run(&name, &mut command, wait, OUTPUT, Halt::OnStop).map_err(Failure::Retry)?;
    if output.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let reason = format!(
        "{name} {} exited {}: {}",
        args.join(" "),
        output.code,
        output.reason()
    );
    let archive = args.first() == Some(&"sim");
    if output.code > 128 || (archive && [HOST_FAULT, INTERRUPTED].contains(&output.code)) {
        Err(Failure::Retry(reason))
    } else {
        Err(Failure::Refused(reason))
    }
}

fn git(checkout: &Path, args: &[&str]) -> Result<String, String> {
    run(Path::new("git"), checkout, args, &[], GIT_WAIT).map_err(|failure| match failure {
        Failure::Refused(reason) | Failure::Retry(reason) => reason,
    })
}

fn read_record(bucket: &Bucket, key: &str, scratch: &Path) -> Result<Vec<u8>, Error> {
    bucket.read(key, scratch, 1 << 20, SHORT)
}

fn point(bucket: &Bucket, scratch: &Path, record: &[u8]) -> Result<bool, String> {
    match read_record(bucket, "current.json", scratch) {
        Ok(current) if current == record => return Ok(false),
        Ok(_) | Err(Error::Missing) => {}
        Err(error) => return Err(format!("current.json: {error}")),
    }
    let path = scratch.join("current.json");
    file::replace(&path, record).map_err(|error| format!("{}: {error}", path.display()))?;
    let replaced = bucket
        .replace("current.json", &path, SHORT)
        .map_err(|error| format!("current.json: {error}"));
    let _ = std::fs::remove_file(&path);
    replaced.map(|()| true)
}

fn put_or_keep(bucket: &Bucket, key: &str, body: &Path) -> Result<bool, String> {
    match bucket.put_once(key, body, LONG) {
        Ok(()) => Ok(true),
        Err(Error::Present) => Ok(false),
        Err(error) => Err(format!("{key}: {error}")),
    }
}

fn record_of(bytes: &[u8], key: &str, head: &str) -> Result<(), String> {
    let record = Commit::parse(bytes).map_err(|error| format!("{key}: {error}"))?;
    if record.commit != head {
        return Err(format!("{key} names commit {}, not {head}", record.commit));
    }
    Ok(())
}

/// Whether the file at `path` holds at most `bound` bytes, the bound every
/// host's fetch applies to it.
fn within(path: &Path, bound: u64) -> Result<bool, String> {
    std::fs::metadata(path)
        .map(|meta| meta.len() <= bound)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Checks that the archive's build record was made from a clean checkout
/// of `head`. The build file is `campaign`'s record envelope, `{"format",
/// "kind", "record", "sha256"}`, and the record's `provenance` must name
/// `head` as the revision, with `dirty` false and no untracked file. A
/// missing or mistyped field fails.
fn clean_record(record: &[u8], head: &str) -> Result<(), String> {
    let parsed: Value = serde_json::from_slice(record)
        .map_err(|error| format!("the archive's build record is no JSON: {error}"))?;
    let provenance = &parsed["record"]["provenance"];
    let revision = provenance["revision"].as_str();
    let dirty = provenance["dirty"].as_bool();
    let untracked = provenance["untracked"].as_u64();
    if revision == Some(head) && dirty == Some(false) && untracked == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "the archive's build record names revision {revision:?}, dirty {dirty:?} and \
             untracked {untracked:?}, not a clean checkout of {head}"
        ))
    }
}

fn once(paths: &Paths, bucket: &Bucket, skipped: &mut Option<String>) -> Result<Value, String> {
    let checkout = &paths.checkout;
    let work = paths.state.join("publish");
    let scratch = paths.state.join("scratch");
    for dir in [&work, &scratch] {
        file::remove_entry(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        file::private_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    }
    git(checkout, &["fetch", "--quiet", "origin", "main"])?;
    let head = git(checkout, &["rev-parse", "origin/main"])?
        .trim()
        .to_owned();
    if !build::is_commit(&head) {
        return Err(format!("origin/main names {head:?}, which is no commit id"));
    }
    // A refused head is skipped only while `origin/main` still names it.
    if skipped.as_deref() != Some(head.as_str()) {
        *skipped = None;
    }
    let commit_key = format!("commits/{head}.json");
    match read_record(bucket, &commit_key, &scratch) {
        Ok(record) => {
            record_of(&record, &commit_key, &head)?;
            let pointed = point(bucket, &scratch, &record)?;
            return Ok(json!({"head": head, "published": false, "current": pointed}));
        }
        Err(Error::Missing) => {}
        Err(error) => return Err(format!("{commit_key}: {error}")),
    }
    if skipped.as_deref() == Some(head.as_str()) {
        return Ok(json!({"head": head, "skipped": true}));
    }
    let refused = |skipped: &mut Option<String>, reason: String| {
        *skipped = Some(head.clone());
        Err(format!("{head} publishes nothing: {reason}"))
    };
    let dirty = git(checkout, &["status", "--porcelain"])?;
    if !dirty.trim().is_empty() {
        return refused(
            skipped,
            format!(
                "the checkout is dirty: {}",
                dirty.lines().next().unwrap_or("")
            ),
        );
    }
    git(checkout, &["checkout", "--quiet", "--detach", &head])?;
    let program = checkout.join("target/release/campaign");
    file::remove_file(&program).map_err(|error| format!("{}: {error}", program.display()))?;
    let built = run(
        Path::new("cargo"),
        checkout,
        &["build", "--release", "-p", "campaign-supervisor"],
        &[],
        BUILD_WAIT,
    );
    match built {
        Ok(_) => {}
        Err(Failure::Refused(reason)) => return refused(skipped, reason),
        Err(Failure::Retry(reason)) => return Err(reason),
    }
    match file::exists(&program) {
        Ok(true) => {}
        Ok(false) => {
            let reason = format!("cargo build wrote no {}", program.display());
            return refused(skipped, reason);
        }
        Err(error) => return Err(format!("{}: {error}", program.display())),
    }
    let archive = work.join("archive");
    let archived = run(
        &program,
        checkout,
        &["sim", "archive", "--output", &archive.to_string_lossy()],
        &[("CARGO_PROFILE_DEV_OPT_LEVEL", "3")],
        BUILD_WAIT,
    );
    match archived {
        Ok(_) => {}
        Err(Failure::Refused(reason)) => return refused(skipped, reason),
        Err(Failure::Retry(reason)) => return Err(reason),
    }
    let record = file::read(&archive.join("build"), 1 << 20)
        .map_err(|error| error.to_string())?
        .ok_or("the archive holds no build record")?;
    if let Err(reason) = clean_record(&record, &head) {
        return refused(skipped, reason);
    }
    let build = file::sha256(&record);
    let tarball = work.join("archive.tar");
    build::pack(&work, "archive", &tarball, Halt::OnStop)?;
    for (path, bound) in [
        (&tarball, build::ARCHIVE_BOUND),
        (&program, build::BINARY_BOUND),
    ] {
        match within(path, bound) {
            Ok(true) => {}
            Ok(false) => {
                let reason = format!("{} is longer than {bound} bytes", path.display());
                return refused(skipped, reason);
            }
            Err(error) => return Err(error),
        }
    }
    let archive_put = put_or_keep(bucket, &build::key(&build, "archive.tar"), &tarball)?;
    let campaign_key = build::key(&build, "campaign");
    let campaign_put = put_or_keep(bucket, &campaign_key, &program)?;
    let campaign = if campaign_put {
        file::sha256_file(&program)
            .map_err(|error| format!("{}: {error}", program.display()))?
            .ok_or("the built campaign binary is missing")?
    } else {
        bucket
            .sha256(&campaign_key)
            .map_err(|error| format!("{campaign_key}: {error}"))?
    };
    let commit = Commit {
        format: 1,
        commit: head.clone(),
        build: build.clone(),
        campaign,
    };
    let bytes = serde_json::to_vec_pretty(&commit).map_err(|error| error.to_string())?;
    let path = work.join("commit.json");
    file::replace(&path, &bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    let record = if put_or_keep(bucket, &commit_key, &path)? {
        bytes
    } else {
        read_record(bucket, &commit_key, &scratch)
            .map_err(|error| format!("{commit_key}: {error}"))?
    };
    record_of(&record, &commit_key, &head)?;
    let pointed = point(bucket, &scratch, &record)?;
    file::remove_entry(&work).map_err(|error| format!("{}: {error}", work.display()))?;
    Ok(json!({
        "head": head,
        "build": build,
        "published": true,
        "archive_stored": archive_put,
        "campaign_stored": campaign_put,
        "current": pointed,
    }))
}

#[cfg(test)]
mod tests {
    use super::{clean_record, within};

    #[test]
    fn an_artifact_past_its_bound_is_refused_and_one_at_it_is_kept() {
        let dir = crate::file::scratch("publish-bound");
        let path = dir.join("archive.tar");
        let file = std::fs::File::create(&path).expect("a file");
        file.set_len(crate::build::ARCHIVE_BOUND)
            .expect("a sparse file at the bound");
        assert_eq!(within(&path, crate::build::ARCHIVE_BOUND), Ok(true));
        file.set_len(crate::build::ARCHIVE_BOUND + 1)
            .expect("a sparse file past the bound");
        assert_eq!(within(&path, crate::build::ARCHIVE_BOUND), Ok(false));
        assert!(within(&dir.join("absent"), 1).is_err());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn only_a_record_of_a_clean_checkout_of_the_head_is_published() {
        let head = "a".repeat(40);
        let record = |provenance: serde_json::Value| {
            serde_json::json!({"format": 1, "kind": "build", "record": {"provenance": provenance},
                               "sha256": "0".repeat(64)})
            .to_string()
        };
        let clean = record(serde_json::json!({"revision": head, "dirty": false, "untracked": 0}));
        assert_eq!(clean_record(clean.as_bytes(), &head), Ok(()));
        // The compact form `campaign sim archive` stores, with every field of
        // the build record, as its record codec writes it.
        let digest = "1".repeat(64);
        let stored = format!(
            concat!(
                r#"{{"format":1,"kind":"build","record":{{"executable":"{d}","libraries":{{}},"#,
                r#""loader":null,"lock":"{d}","machine":"x86_64","provenance":{{"#,
                r#""cargo":"cargo 1.92.0","command":"build --release","dirty":false,"#,
                r#""environment":{{}},"native":{{"install_record":"x86_64.json","#,
                r#""install_record_sha256":"{d}","link_plan_sha256":"{d}","package":"spdk-sys"}},"#,
                r#""revision":"{h}","target":"x86_64-unknown-linux-gnu","toolchain":"rustc 1.92.0","#,
                r#""untracked":0}}}},"sha256":"{d}"}}"#
            ),
            d = digest,
            h = head
        );
        assert_eq!(clean_record(stored.as_bytes(), &head), Ok(()));
        for refused in [
            serde_json::json!({"provenance": {"revision": head, "dirty": false, "untracked": 0}})
                .to_string(),
            record(serde_json::json!({"revision": "b".repeat(40), "dirty": false, "untracked": 0})),
            record(serde_json::json!({"revision": head, "dirty": true, "untracked": 0})),
            record(serde_json::json!({"revision": head, "dirty": false, "untracked": 1})),
            record(serde_json::json!({"revision": head, "dirty": "false", "untracked": 0})),
            record(serde_json::json!({"revision": head, "untracked": 0})),
            "build of a head".to_owned(),
        ] {
            assert!(
                clean_record(refused.as_bytes(), &head).is_err(),
                "{refused}"
            );
        }
    }
}
