//! The fake worker follows case plans and records the process launch facts.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use super::cases::copy_tree;

/// The variable that makes this executable the fake worker.
pub(crate) const PLAN: &str = "CAMPAIGN_FAKE_WORKER";

pub(crate) const LISTING: &str = include_str!("../../testdata/listing.txt");
pub(crate) const COUNTING: &str = include_str!("../../testdata/counting.summary");

/// Executes a worker form under the case plan. `FORM.out` and `FORM.exit`
/// supply its output and exit. A `triage` plan selects phase names from
/// input and output paths. Run writes the supplied manifest’s canonical
/// bytes and `FORM.records` turns, defaulting to two. Replay and reduce
/// copy the input into their output bundles; `FORM.bundle` supplies a
/// planned replacement. `FORM.nobundle` keeps the output absent.
/// Under a `triage` plan, inspect compares supplied and recorded manifests
/// outside their CPU lines and exits 2 for a mismatch.
/// Session plans use `FORM.tree`, `edit`, `tail`, `symlink` and `notree`.
/// A `FORM.prefix` plan publishes `window-1-entered` after window 0 and performs
/// its action at that boundary. `complete` retains the fully written unindexed chunk.
/// Each form records its call and launch facts, then performs `FORM.action`.
/// The worker executes on its single main thread.
pub(crate) fn worker(dir: &Path) -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag: &str| {
        let at = args.iter().position(|arg| arg == flag)?;
        args.get(at + 1).cloned()
    };
    let mut form = if args == ["--capabilities"] {
        "capabilities"
    } else if value("--bundle").is_some() {
        "run"
    } else if value("--inspect").is_some() {
        "inspect"
    } else if value("--replay").is_some() {
        "replay"
    } else if value("--branch").is_some() {
        "branch"
    } else if value("--explore").is_some() {
        "explore"
    } else if value("--session").is_some() {
        "session"
    } else if value("--replay-session").is_some() {
        "replay-session"
    } else if value("--reduce").is_some() {
        "reduce"
    } else {
        return ExitCode::from(2);
    };
    let phase;
    if dir.join("triage").exists() {
        phase = if let Some(input) = value("--inspect") {
            let input = Path::new(&input);
            match input.file_name().and_then(|name| name.to_str()) {
                Some("input") => "inspect-original".to_owned(),
                Some("regression.bundle") => "inspect-candidate".to_owned(),
                Some("panic-original.bundle") => "inspect-panic-original".to_owned(),
                Some("panic-candidate.bundle") => "inspect-panic-candidate".to_owned(),
                Some("replay.bundle") => format!(
                    "inspect-{}",
                    input
                        .parent()
                        .expect("a parent")
                        .file_name()
                        .expect("a name")
                        .to_str()
                        .expect("UTF-8")
                ),
                _ => "inspect".to_owned(),
            }
        } else if form == "replay" {
            Path::new(&value("--output").expect("an output"))
                .file_name()
                .expect("a name")
                .to_str()
                .expect("UTF-8")
                .to_owned()
        } else if form == "run" {
            Path::new(&value("--bundle").expect("a bundle"))
                .file_stem()
                .expect("a name")
                .to_str()
                .expect("UTF-8")
                .to_owned()
        } else {
            form.to_owned()
        };
        form = &phase;
    }
    let plan = |name: &str| fs::read_to_string(dir.join(format!("{form}.{name}"))).ok();
    let mut calls = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("calls"))
        .expect("the calls file opens");
    writeln!(calls, "{form}").expect("the call is recorded");
    let mut stdin = Vec::new();
    std::io::stdin()
        .read_to_end(&mut stdin)
        .expect("stdin reads");
    // SAFETY: these calls take integers or a writable integer and touch no
    // other memory.
    let (leader, deathsig) = unsafe {
        let mut signal: libc::c_int = 0;
        let none: libc::c_ulong = 0;
        libc::prctl(libc::PR_GET_PDEATHSIG, &raw mut signal, none, none, none);
        (libc::getpgrp() == libc::getpid(), signal)
    };
    let status = fs::read_to_string("/proc/self/status").expect("the status reads");
    let blocked = status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .expect("the status names the blocked signals")
        .trim()
        .to_owned();
    let inspected = value("--inspect").map(|path| {
        let bytes = fs::read(&path).expect("the inspect input reads");
        (
            path,
            campaign_supervisor::record::Digest::of(&bytes).to_string(),
        )
    });
    let seen = format!(
        "pid={}\nleader={leader}\ndeathsig={deathsig}\nstdin={}\nblocked={blocked}\nlibraries={}\nmanifest={}\ninspect={}\ninspect_digest={}\ncwd={}\n",
        std::process::id(),
        stdin.len(),
        std::env::var("LD_LIBRARY_PATH").unwrap_or_default(),
        value("--manifest").unwrap_or_default(),
        inspected.as_ref().map_or("", |(path, _)| path),
        inspected.as_ref().map_or("", |(_, digest)| digest),
        std::env::current_dir()
            .expect("a working directory")
            .display(),
    );
    let seen = format!(
        "{seen}args={}\n",
        serde_json::to_string(&args).expect("argv JSON")
    );
    let parent = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .expect("status names the parent")
        .trim();
    let launcher = fs::read(format!("/proc/{parent}/cmdline")).unwrap_or_default();
    let launcher: Vec<_> = launcher
        .split(|byte| *byte == 0)
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8_lossy(word).into_owned())
        .collect();
    let seen = format!(
        "{seen}launcher_args={}\n",
        serde_json::to_string(&launcher).expect("launcher argv JSON")
    );
    publish(&dir.join(format!("{form}.seen")), seen.as_bytes());
    if value("--bundle").is_some() && plan("nobundle").is_none() {
        let manifest = fs::read_to_string(value("--manifest").expect("a manifest"))
            .expect("the manifest reads");
        let manifest = plan("manifest").unwrap_or(manifest);
        let records = plan("records").map_or(2, |count| count.trim().parse().expect("a count"));
        fs::write(
            value("--bundle").expect("a bundle"),
            fs::read(dir.join(format!("{form}.bundle"))).unwrap_or_else(|_| {
                let canonical = manifest
                    .lines()
                    .filter(|line| !line.starts_with("cpu = "))
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                bundle(&canonical, records)
            }),
        )
        .expect("the bundle is written");
    }
    if let Some(input) = value("--replay").or_else(|| value("--reduce"))
        && plan("nobundle").is_none()
    {
        let output = value("--output").expect("an output");
        fs::create_dir(&output).expect("the output is new");
        let input = fs::read(input).expect("the input reads");
        let bytes = fs::read(dir.join(format!("{form}.bundle"))).unwrap_or(input);
        let name = if value("--reduce").is_some() {
            "regression.bundle"
        } else {
            "replay.bundle"
        };
        fs::write(Path::new(&output).join(name), &bytes).expect("the bundle is copied");
        if value("--reduce").is_some() {
            fs::write(
                Path::new(&output).join("regression.manifest"),
                fs::read(dir.join(format!("{form}.manifest"))).unwrap_or_else(|_| {
                    fs::read(
                        value("--manifest")
                            .unwrap_or_else(|| dir.join("manifest").display().to_string()),
                    )
                    .expect("the manifest reads")
                }),
            )
            .expect("the manifest copies");
        }
    }
    if dir.join("triage").exists()
        && let Some(input) = value("--inspect")
    {
        let raw = fs::read(input).expect("the inspected bundle reads");
        let mut recorded = Vec::new();
        for record in raw.as_chunks::<48>().0 {
            if record[0] == 2 && record[1] == 1 {
                recorded.extend_from_slice(&record[5..5 + usize::from(record[4])]);
            } else if ![1, 2, 9].contains(&record[0]) {
                break;
            }
        }
        let recorded = String::from_utf8(recorded).expect("manifest UTF-8");
        let supplied = fs::read_to_string(value("--manifest").expect("a manifest"))
            .expect("the manifest reads");
        let canonical = |value: &str| {
            value
                .lines()
                .filter(|line| !line.starts_with("cpu = "))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        if canonical(&recorded) != canonical(&supplied) {
            eprintln!("the inspected bundle was recorded under another manifest");
            return ExitCode::from(2);
        }
    }
    if matches!(form, "branch" | "explore")
        && let Some(source) = plan("tree")
    {
        copy_tree(
            Path::new(source.trim()),
            Path::new(&value("--output").expect("fork output")),
        );
    }
    let mut session_out = None;
    if matches!(form, "session" | "replay-session") && plan("notree").is_none() {
        let source = plan("tree")
            .or_else(|| value("--replay-session"))
            .expect("a session tree");
        let target = value("--output").expect("an output");
        copy_tree(Path::new(source.trim()), Path::new(&target));
        if let Some(edit) = plan("edit") {
            let mut parts = edit.splitn(3, '\n');
            let name = parts.next().expect("a file");
            let from = parts.next().expect("a source");
            let to = parts.next().expect("a replacement");
            let path = Path::new(&target).join(name);
            let bytes = fs::read_to_string(&path).expect("the file reads");
            assert!(bytes.contains(from));
            fs::write(path, bytes.replacen(from, to, 1)).expect("the edit writes");
        }
        if let Some(tail) = plan("tail") {
            fs::write(
                Path::new(&target).join("windows/tail.chunk"),
                tail.as_bytes(),
            )
            .expect("the tail writes");
            let end_path = Path::new(&target).join("end");
            let end = fs::read_to_string(&end_path).expect("the end reads");
            let prefix = end.rsplit_once(" tail=").expect("a tail field").0;
            fs::write(
                end_path,
                format!(
                    "{prefix} tail={}\n",
                    campaign_supervisor::record::Digest::of(tail.as_bytes())
                ),
            )
            .expect("the tail digest writes");
        }
        if plan("prefix").is_some() {
            let index = Path::new(&target).join("index");
            let lines = fs::read_to_string(&index).expect("the index reads");
            fs::write(
                index,
                format!("{}\n", lines.lines().next().expect("a window")),
            )
            .expect("the prefix writes");
            fs::remove_file(Path::new(&target).join("end")).expect("the end removes");
            fs::remove_file(Path::new(&target).join("windows/tail.chunk"))
                .expect("the tail removes");
            if plan("prefix").is_some_and(|value| value.trim() != "complete") {
                fs::write(Path::new(&target).join("windows/000001.chunk"), [3, 10])
                    .expect("the open chunk writes");
            }
            publish(
                &dir.join("window-1-entered"),
                b"window 0 committed; window 1 entered",
            );
            if let Some(action) = plan("action") {
                act(action.trim(), dir);
            }
        }
        if let Some(name) = plan("symlink") {
            let path = Path::new(&target).join(name.trim());
            let outside = dir.join("session-linked-evidence");
            fs::rename(&path, &outside).expect("the entry moves outside the tree");
            std::os::unix::fs::symlink(&outside, &path).expect("the output entry links");
        }
        let index = fs::read_to_string(Path::new(&target).join("index")).expect("the index reads");
        let chain = index
            .lines()
            .last()
            .expect("a window")
            .split_whitespace()
            .find_map(|part| part.strip_prefix("chain="))
            .expect("a chain");
        session_out = Some(if form == "replay-session" {
            format!(
                "replay: reproduced, {} windows, chain {chain}\n",
                index.lines().count()
            )
        } else {
            let end = fs::read_to_string(Path::new(&target).join("end")).expect("the end reads");
            format!(
                "session: {} windows, chain {chain}\n{}\n",
                index.lines().count(),
                end.split(" windows=").next().expect("end facts")
            )
        });
    }
    let out = plan("out").or(session_out).unwrap_or_else(|| match form {
        "capabilities" => LISTING.to_owned(),
        "replay" | "baseline" | "candidate-replay" => {
            let summary = fs::read_to_string(dir.join(format!("inspect-{form}.out")))
                .unwrap_or_else(|_| COUNTING.to_owned());
            let listing = campaign_supervisor::protocol::Listing::parse(LISTING).expect("listing");
            let summary = campaign_supervisor::protocol::Summary::parse(&summary, &listing)
                .expect("planned summary");
            let mut claim = summary.terminal.to_string();
            if let Some(cause) = summary
                .cause
                .and_then(|cause| cause.strip_prefix("violation, ").map(str::to_owned))
            {
                claim.push_str(&format!(", {cause}"));
            }
            format!("replay: reproduced, {claim}\n")
        }
        "reduce" => {
            if plan("exit").is_some_and(|code| code.trim() == "1") {
                String::new()
            } else {
                let raw = fs::read(
                    Path::new(&value("--output").expect("output")).join("regression.bundle"),
                )
                .unwrap_or_default();
                let mut manifest = Vec::new();
                for record in raw.as_chunks::<48>().0 {
                    if record[0] == 2 && record[1] == 1 {
                        manifest.extend_from_slice(&record[5..5 + usize::from(record[4])]);
                    } else if ![1, 2, 9].contains(&record[0]) {
                        break;
                    }
                }
                let manifest = String::from_utf8(manifest).expect("manifest");
                let scenario = manifest
                    .lines()
                    .find_map(|line| line.strip_prefix("scenario = "))
                    .unwrap_or("");
                let panic = fs::read_to_string(dir.join("panic-candidate.out"))
                    .ok()
                    .filter(|output| output.starts_with("run: the run panicked at "))
                    .or_else(|| fs::read_to_string(dir.join("panic-original.out")).ok())
                    .and_then(|output| {
                        output
                            .strip_prefix("run: the run panicked at ")
                            .map(|identity| {
                                format!(", the run panicked at {}", identity.trim_end())
                            })
                    })
                    .unwrap_or_default();
                format!(
                    "reduce: reduced to {} records, scenario {scenario}{panic}\n",
                    raw.len() / 48
                )
            }
        }
        "inspect-panic-original" | "inspect-panic-candidate" => {
            let run = form.strip_prefix("inspect-").expect("inspection");
            let printed = fs::read_to_string(dir.join(format!("{run}.out"))).unwrap_or_default();
            if printed.starts_with("run: ") || printed.is_empty() {
                fs::read_to_string(dir.join("inspect-original.out"))
                    .unwrap_or_else(|_| COUNTING.to_owned())
            } else {
                printed
            }
        }
        "inspect-candidate" if dir.join("panic-original.out").exists() => {
            fs::read_to_string(dir.join("inspect-original.out")).expect("original summary")
        }
        _ => COUNTING.to_owned(),
    });
    print!("{out}");
    std::io::stdout().flush().expect("stdout flushes");
    if let Some(action) = plan("action") {
        act(action.trim(), dir);
    }
    let code = plan("exit").map_or(0, |code| code.trim().parse().expect("an exit code"));
    ExitCode::from(code)
}

/// Publishes `bytes` at `path` by renaming a staged file onto it, so a
/// reader sees the file whole.
fn publish(path: &Path, bytes: &[u8]) {
    let staged = path.with_extension("part");
    fs::write(&staged, bytes).expect("the file is written");
    fs::rename(&staged, path).expect("the file is renamed into place");
}

fn act(action: &str, dir: &Path) {
    let target = || {
        fs::read_to_string(dir.join("rewrite.target"))
            .expect("a target")
            .trim()
            .to_owned()
    };
    match action {
        "hang" => std::thread::sleep(Duration::from_secs(600)),
        "wait-for-release" => {
            let deadline = std::time::Instant::now() + Duration::from_secs(120);
            while !dir.join("release").exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "worker release seam was not reached"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        "corpus-output-limit" => {
            let bytes = vec![0; 1 << 20];
            for index in 0..32 {
                fs::write(format!("probe-output-{index}"), &bytes).expect("probe output");
            }
            std::thread::sleep(Duration::from_secs(600));
        }
        "abort" => std::process::abort(),
        "flood" => {
            let block = vec![b'x'; 1 << 16];
            for _ in 0..=16 {
                let _ = std::io::stdout().write_all(&block);
            }
        }
        "flood-stderr" => {
            let _ = std::io::stderr().write_all(&vec![b'x'; (1 << 20) + 1]);
        }
        "exact-stderr" => {
            std::io::stderr()
                .write_all(&vec![b'x'; 1 << 20])
                .expect("stderr writes");
        }
        "escape" => {
            escape(dir);
            std::thread::sleep(Duration::from_secs(600));
        }
        "escape-exit" => escape(dir),
        "setsid" => setsid(dir),
        "setsid-hang" => {
            setsid(dir);
            std::thread::sleep(Duration::from_secs(600));
        }
        "grow" => {
            fs::OpenOptions::new()
                .write(true)
                .open(target())
                .expect("source")
                .set_len(1 << 40)
                .expect("sparse growth");
        }
        "non-utf8" => std::io::stdout().write_all(&[0xff]).expect("raw stdout"),
        "symlink" => {
            let path = PathBuf::from(target());
            let saved = path.with_extension("real");
            fs::rename(&path, &saved).expect("saved evidence");
            std::os::unix::fs::symlink(saved.file_name().expect("name"), &path)
                .expect("symlink evidence");
        }
        "squat" => {
            let cwd = std::env::current_dir().expect("the working directory");
            fs::write(cwd.join("run.stderr"), b"squatted").expect("the name is taken");
        }
        "remove" => fs::remove_file(target()).expect("it is removed"),
        "replace" => publish(Path::new(&target()), b"changed while the worker ran"),
        "shared" => {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(target(), fs::Permissions::from_mode(0o777))
                .expect("shared ancestor");
        }
        "readonly" => {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(target(), fs::Permissions::from_mode(0o500)).expect("read only");
        }
        "restore" => {
            let path = target();
            let original = fs::read(&path).expect("original input");
            fs::write(&path, b"changed").expect("changed input");
            fs::write(&path, original).expect("restored input");
        }
        "rewrite" => {
            fs::write(target(), b"changed while the worker ran").expect("it is rewritten");
        }
        "chmod" => {
            let target = target();
            let permissions = fs::metadata(&target).expect("it exists").permissions();
            fs::set_permissions(&target, permissions).expect("it is chmodded");
        }
        other => panic!("no action {other}"),
    }
}

fn escape(dir: &Path) {
    // SAFETY: the process runs one thread, as `worker` documents, so the
    // child of `fork` holds no lock of another thread and runs any code.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        // SAFETY: the child runs one thread too.
        let grandchild = unsafe { libc::fork() };
        assert!(grandchild >= 0, "grandchild fork failed");
        if grandchild == 0 {
            std::thread::sleep(Duration::from_secs(600));
        } else {
            publish(&dir.join("escapee"), grandchild.to_string().as_bytes());
        }
        std::process::exit(0);
    }
    let mut status = 0;
    // SAFETY: the writable local status outlives waitpid.
    assert_eq!(unsafe { libc::waitpid(child, &raw mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

/// Forks a child that leaves the worker's session and process group,
/// records its process ID in `escapee` and sleeps holding the worker's
/// standard output and error; the worker continues once `escapee` exists.
fn setsid(dir: &Path) {
    // SAFETY: the process runs one thread, as `worker` documents, so the
    // child of `fork` holds no lock of another thread and runs any code.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    let escapee = dir.join("escapee");
    if child == 0 {
        // SAFETY: `setsid` takes no arguments and touches no memory.
        assert_eq!(unsafe { libc::setsid() }, unsafe { libc::getpid() });
        publish(&escapee, std::process::id().to_string().as_bytes());
        std::thread::sleep(Duration::from_secs(600));
        std::process::exit(0);
    }
    // The worker exits only once the child left the group, and aborts when
    // the child records nothing within ten seconds.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !escapee.exists() {
        if std::time::Instant::now() > deadline {
            std::process::abort();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// A raw bundle: a Begin record, `manifest`'s text in 43-byte field
/// chunks, then `body` turn records.
pub(crate) fn bundle(manifest: &str, body: usize) -> Vec<u8> {
    let mut out = vec![0; 48];
    out[0] = 1;
    for (at, chunk) in manifest.as_bytes().chunks(43).enumerate() {
        let mut record = [0; 48];
        record[0] = 2;
        record[1] = 1;
        record[2..4].copy_from_slice(&u16::try_from(at).expect("few chunks").to_le_bytes());
        record[4] = u8::try_from(chunk.len()).expect("a chunk is short");
        record[5..5 + chunk.len()].copy_from_slice(chunk);
        out.extend_from_slice(&record);
    }
    for _ in 0..body {
        let mut record = [0; 48];
        record[0] = 4;
        out.extend_from_slice(&record);
    }
    out
}
