//! The stand-ins of a run's children: `campaign` and `python3` are this test executable started again in
//! the stand-in's role, by a POSIX `sh` wrapper the fixture writes, which passes the child's arguments
//! after `--` and hands the real standard output over as descriptor 3 while libtest's own lines go to
//! `/dev/null`.
//!
//! The `campaign` stand-in reads the mode of the tree it archives, or of the archive it sweeps, to act out
//! one outcome; it logs each call's arguments as a JSON array in `STANDIN_LOG`. A sweep adds 200 runs to
//! each profile, and 100 to `slow`; a seed check passes only on the archive of mode `base` and only for a
//! seed other than 665, 666, 777 and 555. The `python3` stand-in either runs the head's staged helper,
//! reading the tree's mode, or answers the question to it from the staged file's text: the verdict texts
//! of its `RESULTS` line, and `reported` where the file defines it.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kestrike_tools::json::{self, Integer, Object, Value};
use kestrike_tools::python::hexdigest;
use kestrike_tools::text::Text;

pub const ROLE: &str = "PLANT_STANDIN";
/// The file beside the call log where a stand-in that panics writes its role, its arguments and the
/// panic, so a broken stand-in fails its case and reads as no child's outcome.
pub const FAILED: &str = "standin-failed";
const ROLE_TEST: &str = "plant_runner::standins::role";

/// `wrapper` is the `sh` text that starts this test executable in `role`.
pub fn wrapper(role: &str) -> String {
    let exe = std::env::current_exe().expect("the test executable is known");
    format!(
        "#!/bin/sh\n{ROLE}={role}\nexport {ROLE}\nexec '{}' --exact {ROLE_TEST} --nocapture \
         --test-threads 1 -- \"$@\" 3>&1 1>/dev/null\n",
        exe.display()
    )
}

/// The role runs only in a stand-in's process, which it ends with the stand-in's exit.
#[test]
fn role() {
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let args: Vec<String> = std::env::args()
        .skip_while(|arg| arg != "--")
        .skip(1)
        .collect();
    if let Some(log) = var("STANDIN_LOG") {
        let failed = Path::new(&log).with_file_name(FAILED);
        let shown = format!("{role:?} {args:?}");
        std::panic::set_hook(Box::new(move |info| {
            append(&failed, &format!("{shown}: {info}\n"));
        }));
    }
    // SAFETY: the wrapper opens descriptor 3 as the caller's standard output, and nothing else in this
    // process owns it.
    let mut out = unsafe { File::from_raw_fd(3) };
    let code = match role.to_str() {
        Some("campaign") => campaign(&args, &mut out),
        Some("python3") => python(&args, &mut out),
        other => panic!("no stand-in plays {other:?}"),
    };
    let _ = out.flush();
    std::process::exit(code);
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn write(path: &Path, text: &str) {
    fs::write(path, text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

fn append(path: &Path, text: &str) {
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .and_then(|mut log| log.write_all(text.as_bytes()))
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

fn string(text: &str) -> Value {
    Value::String(Text::from(text))
}

fn int(number: u64) -> Value {
    Value::Integer(Integer::from(number))
}

fn number(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Integer(number)) => number.to_string().parse().expect("a stand-in count"),
        _ => 0,
    }
}

fn digest(mode: &str) -> String {
    hexdigest(mode.as_bytes())
}

fn option<'a>(args: &'a [String], name: &str) -> &'a str {
    let at = args
        .iter()
        .position(|arg| arg == name)
        .expect("the option is given");
    &args[at + 1]
}

fn mode_of(archive: &Path) -> String {
    read(&archive.join("mode")).trim().to_owned()
}

/// `hold_until_released` marks that SIGTERM arrived beside `log`, waits at most 30 s for the test's
/// release, marks that it ends, and exits 4; with no SIGTERM in 60 s it exits 0.
fn hold_until_released(log: &Path) -> ! {
    let place = log.parent().expect("a log lies in the scratch directory");
    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(libc::SIGTERM, Arc::clone(&term)).expect("the handler installs");
    write(&place.join("ready"), "");
    for _ in 0..1200 {
        if term.load(Ordering::SeqCst) {
            write(&place.join("handling"), &libc::SIGTERM.to_string());
            for _ in 0..600 {
                if place.join("release").exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            write(&place.join("terminated"), &libc::SIGTERM.to_string());
            std::process::exit(4);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::process::exit(0);
}

/// A suspect line of a mode: the profile (`None` for the last swept), the run, the seed and the class.
type Line = (Option<&'static str>, u64, u64, &'static str);

/// The modes with the suspect line `ONE`: a violation in run 7 of the last swept profile, seed 42.
const ONE_MODES: [&str; 26] = [
    "catch",
    "hangconfirm",
    "hangseed",
    "catchalarm",
    "refuse",
    "mismatch",
    "watchdog",
    "otherprofile",
    "otherseed",
    "queued",
    "nomanifest",
    "wide",
    "deepconfirm",
    "othermanifest",
    "noid",
    "badrun",
    "boolrun",
    "confirmfail",
    "held",
    "heldnone",
    "heldother",
    "heldrejected",
    "heldomitted",
    "heldmixed",
    "heldpaused",
    "otherunlisted",
];
const HELD: [&str; 7] = [
    "held",
    "heldnone",
    "heldother",
    "heldrejected",
    "heldomitted",
    "heldmixed",
    "heldpaused",
];

/// `suspects` are the suspect lines a sweep of `mode` writes.
fn suspects(mode: &str) -> Option<Vec<Line>> {
    let one: Vec<Line> = vec![(None, 7, 42, "violation")];
    let eight = (20..28).map(|run| (None, run, 42, "replay differs"));
    let lines: Vec<Line> = match mode {
        "panic" => vec![(None, 7, 42, "panic")],
        "second" => vec![(None, 7, 666, "violation"), (None, 8, 42, "violation")],
        "passthenfail" => vec![(None, 7, 42, "violation"), (None, 8, 666, "violation")],
        "dup" => vec![(None, 7, 666, "violation"), (None, 7, 666, "violation")],
        "headfail" => vec![(None, 7, 666, "violation")],
        "lonehead" => vec![(None, 7, 665, "violation")],
        "rejectseed" => vec![(None, 7, 777, "violation")],
        "oddthen" => vec![(None, 7, 777, "violation"), (None, 8, 42, "violation")],
        "violatehead" => vec![(None, 7, 665, "violation"), (None, 8, 42, "violation")],
        "laterfinding" | "lowkey" | "oddfinding" => {
            vec![(None, 7, 42, "violation"), (None, 8, 42, "violation")]
        }
        "other" => vec![(None, 7, 42, "wall limit")],
        "gapfirst" => vec![
            (Some("gap"), 7, 42, "violation"),
            (Some("a"), 8, 42, "violation"),
        ],
        "gaplast" => vec![
            (Some("a"), 7, 42, "violation"),
            (Some("gap"), 8, 42, "violation"),
        ],
        "replaydiffers" => vec![
            (None, 7, 42, "violation"),
            (None, 7, 42, "replay differs"),
            (None, 8, 42, "violation"),
        ],
        "replayonly" => vec![(None, 7, 42, "violation"), (None, 7, 42, "replay differs")],
        "replayunlisted" | "replaylisted" => one.iter().copied().chain(eight).collect(),
        "replayelsewhere" => vec![
            (Some("a"), 7, 42, "violation"),
            (Some("b"), 8, 42, "violation"),
        ],
        "manyviolations" | "nokeys" | "oddkeys" | "emptykeys" | "shortkeys" => one,
        "history" => vec![(Some("h-history"), 3, 42, "violation")],
        "catchbroken" => vec![
            (Some("a"), 7, 42, "violation"),
            (Some("ghost"), 8, 42, "violation"),
        ],
        "noresult" => vec![(None, 7, 888, "violation")],
        "oddpass" => vec![(None, 7, 555, "violation")],
        "twopass" => vec![(None, 7, 42, "violation"), (None, 8, 43, "violation")],
        "longest" => vec![(None, 7, u64::MAX, "violation")],
        _ if ONE_MODES.contains(&mode) => one,
        _ => return None,
    };
    Some(lines)
}

/// `unlisted` are the suspects a sweep of `mode` counts under a key past the lines it writes: the
/// profile (`None` for the last swept), the key and the count.
fn unlisted(mode: &str) -> Option<(Option<&'static str>, &'static str, u64)> {
    match mode {
        "replayunlisted" => Some((None, "replay differs: a rule", 1)),
        "otherunlisted" => Some((None, "other", 1)),
        "manyviolations" => Some((None, "violation: a rule", 12)),
        "replayelsewhere" => Some((Some("a"), "replay differs: x", 1)),
        _ => None,
    }
}

fn object(value: &mut Value) -> &mut Object {
    match value {
        Value::Object(object) => object,
        other => panic!("{other:?} is no object"),
    }
}

/// `entry` is the member `name` of `object`, inserted as `default` where it is missing.
fn entry<'a>(object: &'a mut Object, name: &str, default: Value) -> &'a mut Value {
    if object.get(name).is_none() {
        object.insert(name, default);
    }
    object.get_mut(name).expect("the member stands")
}

fn add(object: &mut Object, name: &str, more: u64) {
    let now = number(object.get(name));
    object.insert(name, int(now + more));
}

/// `seen_replacement` appends the `GIT_NO_REPLACE_OBJECTS` the stand-in `role` was given, or `unset`,
/// as a line of `ROLE-no-replace` in `place`: one line a call.
fn seen_replacement(place: &Path, role: &str) {
    let seen = std::env::var("GIT_NO_REPLACE_OBJECTS").unwrap_or_else(|_| "unset".to_owned());
    append(
        &place.join(format!("{role}-no-replace")),
        &format!("{seen}\n"),
    );
}

fn say(out: &mut File, line: &str) {
    out.write_all(line.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .expect("the stand-in's output is written");
}

fn json_line(object: &Object) -> String {
    json::text(&Value::Object(object.clone()))
}

/// `campaign` acts out one `campaign` call and returns its exit.
fn campaign(args: &[String], out: &mut File) -> i32 {
    let log = PathBuf::from(var("STANDIN_LOG").expect("STANDIN_LOG names the call log"));
    let logged = Value::Array(args.iter().map(|arg| string(arg)).collect());
    append(&log, &format!("{}\n", json::text(&logged)));
    if let Some(block) = var("STANDIN_BLOCK_SCORE") {
        let _ = fs::create_dir(block);
    }
    let place = log
        .parent()
        .expect("the log lies in the scratch directory")
        .to_path_buf();
    seen_replacement(&place, "campaign");
    match args.first().map(String::as_str) {
        Some("sim") if args.get(1).is_some_and(|arg| arg == "archive") => {
            archive(args, &place, &log, out)
        }
        Some("sweep") => sweep(args, &log),
        Some("sweep-status") => status(args, out),
        Some("confirm") => confirm(args, out),
        Some("sim") if args.get(1).is_some_and(|arg| arg == "run") => seed(args, out),
        _ => 2,
    }
}

fn archive(args: &[String], place: &Path, log: &Path, out: &mut File) -> i32 {
    let mode = read(Path::new("mode")).trim().to_owned();
    let target = PathBuf::from(var("CARGO_TARGET_DIR").expect("the build names its target"));
    fs::create_dir_all(&target).expect("the target is made");
    write(&target.join("built"), &mode);
    if mode == "nobuild" || (mode == "base" && var("STANDIN_BASE_FAIL").is_some()) {
        return 3;
    }
    if mode == "refusedarchive" {
        return 2;
    }
    if mode == "lock" {
        let here = std::env::current_dir().expect("the build's directory is known");
        let locked = Command::new("git")
            .args(["worktree", "lock", "--reason", "a test"])
            .arg(here)
            .status()
            .expect("git starts");
        assert!(locked.success(), "the stand-in locks its worktree");
    }
    if mode == "hangbuild" {
        hold_until_released(log);
    }
    let output = PathBuf::from(option(args, "--output"));
    fs::create_dir(&output).expect("the archive is made");
    write(&output.join("mode"), &mode);
    if mode == "otherlock" {
        write(&output.join("Cargo.lock"), "another resolution\n");
    } else if mode == "linklock" {
        fs::copy("Cargo.lock", output.join("kept.lock")).expect("the lockfile is kept");
        std::os::unix::fs::symlink("kept.lock", output.join("Cargo.lock")).expect("linked");
    } else if mode == "dirlock" {
        fs::create_dir(output.join("Cargo.lock")).expect("the directory is made");
    } else if mode != "nolock" && mode != "nolockarchive" {
        fs::copy("Cargo.lock", output.join("Cargo.lock")).expect("the lockfile is kept");
    }
    let mut seen = Object::new();
    for name in [
        "CARGO_PROFILE_DEV_OPT_LEVEL",
        "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
    ] {
        seen.insert(
            name,
            std::env::var(name).map_or(Value::Null, |value| string(&value)),
        );
    }
    seen.insert("lockfile", string(&read(Path::new("Cargo.lock"))));
    if let Ok(lockfile) = std::env::var("CARGO_RESOLVER_LOCKFILE_PATH") {
        write(&place.join("archive-lockfile-path"), &lockfile);
    }
    let watched =
        PathBuf::from(var("STANDIN_WATCH").expect("STANDIN_WATCH names the proof's place"));
    let mut proof = Object::new();
    for name in ["target", "tree"] {
        proof.insert(name, Value::Bool(watched.join(name).exists()));
    }
    seen.insert("proof", Value::Object(proof));
    write(&output.join("env"), &json_line(&seen));
    let mut pins = Object::new();
    pins.insert("build", string(&digest(&mode)));
    pins.insert("executable", string(&format!("x-{mode}")));
    pins.insert("platform", string(&format!("p-{mode}")));
    pins.insert("toolchain", string(&format!("t-{mode}")));
    say(out, &json_line(&pins));
    0
}

fn profile_totals() -> Value {
    let mut totals = Object::new();
    for name in ["next", "runs", "pass", "suspects", "replays"] {
        totals.insert(name, int(u64::from(name == "replays")));
    }
    totals.insert("uncredited", Value::Object(Object::new()));
    Value::Object(totals)
}

fn write_suspects(mode: &str, root: &Path, profiles: &[String], state: &mut Object) {
    let Some(lines) = suspects(mode) else {
        return;
    };
    let last = profiles.last().expect("a sweep names a profile").as_str();
    let mut written = Vec::new();
    for (profile, run, seed, kind) in lines {
        let profile = profile.unwrap_or(last);
        let key = format!("{kind}: a rule");
        let mut line = Object::new();
        line.insert("profile", string(profile));
        line.insert("run", int(run));
        line.insert("seed", int(seed));
        line.insert("class", string(kind));
        line.insert("key", string(&key));
        line.insert("build", string(&digest(mode)));
        let summary = if mode == "wide" {
            let mut summary = Object::new();
            summary.insert("rule", string("a rule\u{2028}across a line separator"));
            Value::Object(summary)
        } else {
            Value::Null
        };
        line.insert("summary", summary);
        written.push(json_line(&line).replace("\\u2028", "\u{2028}"));
        let profiles = object(entry(state, "profiles", Value::Object(Object::new())));
        let mut fresh = Object::new();
        for (name, value) in [("next", 1), ("runs", 1), ("pass", 0), ("suspects", 0)] {
            fresh.insert(name, int(value));
        }
        let totals = object(entry(profiles, profile, Value::Object(fresh)));
        add(totals, "suspects", 1);
        let keys = object(entry(totals, "suspect_keys", Value::Object(Object::new())));
        add(keys, &key, 1);
    }
    let profiles = object(state.get_mut("profiles").expect("the state holds profiles"));
    if let Some((profile, key, more)) = unlisted(mode) {
        let totals = object(
            profiles
                .get_mut(profile.unwrap_or(last))
                .expect("the profile stands"),
        );
        add(totals, "suspects", more);
        add(
            object(totals.get_mut("suspect_keys").expect("keys stand")),
            key,
            more,
        );
    }
    let totals = object(profiles.get_mut(last).expect("the last profile stands"));
    match mode {
        "nokeys" => drop(totals.remove("suspect_keys")),
        "oddkeys" => object(totals.get_mut("suspect_keys").expect("keys stand"))
            .insert("violation: a rule", Value::Bool(true)),
        "emptykeys" => totals.insert("suspect_keys", Value::Object(Object::new())),
        "shortkeys" => add(totals, "suspects", 1),
        "lowkey" => {
            let mut keys = Object::new();
            keys.insert("violation: a rule", int(1));
            keys.insert("violation: b", int(1));
            totals.insert("suspect_keys", Value::Object(keys));
        }
        _ => {}
    }
    write(
        &root.join("suspects.jsonl"),
        &format!("{}\n", written.join("\n")),
    );
}

fn sweep(args: &[String], log: &Path) -> i32 {
    let root = PathBuf::from(option(args, "--root"));
    let mode = mode_of(Path::new(option(args, "--archive")));
    if mode == "hang" {
        hold_until_released(log);
    }
    let profiles: Vec<String> = option(args, "--profiles")
        .split(',')
        .map(str::to_owned)
        .collect();
    if !root.exists() {
        fs::create_dir(&root).expect("the root is made");
        kestrike_tools_chmod(&root, 0o700);
    }
    let _ = fs::create_dir(root.join("manifests"));
    let path = root.join("state.json");
    let mut state = if path.exists() {
        match json::parse(&read(&path)).expect("the state is JSON") {
            Value::Object(state) => state,
            other => panic!("{other:?}"),
        }
    } else {
        let mut state = Object::new();
        state.insert("profiles", Value::Object(Object::new()));
        state
    };
    let all = object(state.get_mut("profiles").expect("the state holds profiles"));
    for profile in &profiles {
        if mode == "nomanifest" {
            continue;
        }
        if mode == "catchbroken" && profile == "ghost" {
            let mut ghost = Object::new();
            for (name, value) in [("next", 400), ("runs", 300), ("pass", 300), ("suspects", 0)] {
                ghost.insert(name, int(value));
            }
            entry(all, profile, Value::Object(ghost));
            continue;
        }
        let totals = object(entry(all, profile, profile_totals()));
        let added = if mode == "short" {
            0
        } else if profile == "slow" {
            100
        } else {
            200
        };
        add(totals, "next", added);
        let counted = if added == 0 { 0 } else { added - 50 };
        add(totals, "runs", counted);
        add(totals, "pass", counted);
        if mode == "norun" {
            totals.insert("runs", int(0));
            totals.insert("pass", int(0));
        }
        if mode == "overrun" {
            let next = number(totals.get("next"));
            totals.insert("runs", int(next + 1));
        }
        if mode == "nocount" {
            totals.remove("suspects");
        }
        if profile == "gap" {
            continue;
        }
        let build = digest(&mode);
        write(
            &root.join("manifests").join(format!("{profile}.manifest")),
            &format!(
                "version = 2\nprofile = {profile}\nroot = 1\nexecutable = x-{mode}\n\
                 toolchain = t-{mode}\nbuild = {build}\nplatform = p-{mode}\nturns = 9\n"
            ),
        );
    }
    let listed = root.join("suspects.jsonl");
    if suspects(&mode).is_some() && !listed.exists() {
        write_suspects(&mode, &root, &profiles, &mut state);
    }
    if mode == "loneline" && !listed.exists() {
        write(
            &listed,
            "{\"profile\": \"a\", \"run\": 3, \"seed\": 5, \"class\": \"wall limit\", \"key\": \"wall limit\"}\n",
        );
    }
    if mode == "cutline" && !listed.exists() {
        write(&listed, "{\"profile\": \"a\", \"run\": 3");
    }
    let all = object(state.get_mut("profiles").expect("the state holds profiles"));
    if mode == "disorder" {
        let a = object(all.get_mut("a").expect("a is swept"));
        let runs = number(a.get("runs"));
        a.insert("pass", int(runs + 1));
    }
    if mode == "historynocount" {
        let mut history = Object::new();
        for name in ["next", "runs", "pass"] {
            history.insert(name, int(5));
        }
        all.insert("h-history", Value::Object(history));
    }
    if mode == "badline" && !listed.exists() {
        write(&listed, "{\"profile\": \"a\", \"run\": \"seven\"}\n");
    }
    if mode == "dirlog" {
        let _ = fs::create_dir(&listed);
    }
    let first = || string(&profiles[0]);
    let planned = |words: &str| {
        let mut keyed = Object::new();
        keyed.insert(profiles[0].as_str(), Value::Array(vec![string(words)]));
        Value::Object(keyed)
    };
    match mode.as_str() {
        "alarm" | "catchalarm" => state.insert("alarm", int(1)),
        "nopass" => state.insert("no_pass", Value::Array(vec![first()])),
        "unreached" => state.insert("unreached", planned("a required event")),
        "nowindow" => state.insert("no_window", planned("a planned window")),
        _ => {}
    }
    let named = if mode == "othercampaign" {
        "another"
    } else {
        option(args, "--campaign")
    };
    state.insert("campaign", string(named));
    write(&path, &json_line(&state));
    match mode.as_str() {
        "damaged" => 4,
        "alarm" | "catchalarm" | "nopass" | "unreached" | "nowindow" | "exitone" => 1,
        _ => 0,
    }
}

fn kestrike_tools_chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("the mode is set");
}

fn load(path: &Path) -> Object {
    match json::parse(&read(path)).expect("the stand-in's state is JSON") {
        Value::Object(state) => state,
        other => panic!("{other:?} is no object"),
    }
}

fn status(args: &[String], out: &mut File) -> i32 {
    let root = PathBuf::from(option(args, "--root"));
    let state = load(&root.join("state.json"));
    let mode = mode_of(
        &root
            .parent()
            .expect("the root lies in a plant's place")
            .join("archive"),
    );
    let mut total: u64 = match state.get("profiles") {
        Some(Value::Object(profiles)) => profiles
            .iter()
            .map(|(_, totals)| match totals {
                Value::Object(totals) => number(totals.get("suspects")),
                _ => 0,
            })
            .sum(),
        _ => 0,
    };
    if mode == "rootsuspect" {
        total += 1;
    }
    if mode == "statusfail" {
        return 2;
    }
    if mode == "badbytes" {
        out.write_all(b"\xff\xfe\n").expect("the bytes are written");
        return 0;
    }
    let total = match mode.as_str() {
        "booltotal" => Value::Bool(false),
        "floattotal" => Value::Float(0.0),
        _ => int(total),
    };
    let tally = |caught| {
        let mut tally = Object::new();
        tally.insert("caught", int(caught));
        tally.insert("missed", int(0));
        Value::Object(tally)
    };
    let mut counts = Object::new();
    if mode == "othercounts" {
        counts.insert("nodes", int(5));
    }
    let mut printed = Object::new();
    printed.insert("counts", Value::Object(counts));
    printed.insert("suspects", total);
    printed.insert("controls", tally(3));
    printed.insert("histories", tally(2));
    for (name, value) in state.iter() {
        printed.insert(name.clone(), value.clone());
    }
    say(out, &json_line(&printed));
    0
}

fn wide(value: &Value) -> u128 {
    match value {
        Value::Integer(number) => number.to_string().parse().expect("a stand-in integer"),
        other => panic!("{other:?} is no integer"),
    }
}

fn big(number: u128) -> Value {
    Value::Integer(Integer::from_digits(false, &number.to_string()).expect("digits"))
}

fn confirm(args: &[String], out: &mut File) -> i32 {
    let root = PathBuf::from(option(args, "--root"));
    let mode = mode_of(Path::new(option(args, "--archive")));
    if mode == "hangconfirm" {
        hold_until_released(&PathBuf::from(
            var("STANDIN_LOG").expect("the call log is named"),
        ));
    }
    if mode == "deepconfirm" {
        say(out, &"[".repeat(100_000));
        return 0;
    }
    if mode == "confirmfail" {
        return 2;
    }
    let mut findings = Vec::new();
    let listed = read(&root.join("suspects.jsonl"));
    let lines: Vec<&str> = listed.split('\n').collect();
    for (number, line) in lines[..lines.len() - 1].iter().enumerate() {
        let Value::Object(suspect) = json::parse(line).expect("a suspect line is JSON") else {
            panic!("a suspect line is an object");
        };
        if mode == "laterfinding" && number == 0 {
            continue;
        }
        let run = wide(suspect.get("run").expect("run")) + u128::from(mode == "mismatch");
        let Some(Value::String(listed_profile)) = suspect.get("profile") else {
            panic!("a suspect names its profile");
        };
        let profile = if mode == "otherprofile" {
            Text::from("other")
        } else {
            listed_profile.clone()
        };
        let seed = wide(suspect.get("seed").expect("seed")) + u128::from(mode == "otherseed");
        let template = root
            .join("manifests")
            .join(format!("{listed_profile}.manifest"));
        let text = if template.exists() {
            read(&template)
        } else {
            String::new()
        };
        let seeded: String = text
            .lines()
            .map(|line| {
                let line = if line.starts_with("root = ") {
                    format!("root = {seed}")
                } else {
                    line.to_owned()
                };
                line + "\n"
            })
            .collect();
        let manifest = if mode == "othermanifest" {
            "0".repeat(64)
        } else {
            hexdigest(seeded.as_bytes())
        };
        let mut experiment = Object::new();
        experiment.insert("profile", Value::String(profile));
        let run = match mode.as_str() {
            "badrun" => string(&run.to_string()),
            "boolrun" => Value::Bool(true),
            _ => big(run),
        };
        experiment.insert("run", run);
        let mut job = Object::new();
        job.insert("experiment", Value::Object(experiment));
        job.insert("seed", big(seed));
        job.insert("manifest_sha256", string(&manifest));
        let kind = if mode == "watchdog" {
            string("watchdog")
        } else {
            suspect.get("class").expect("class").clone()
        };
        let mut admission = Object::new();
        admission.insert("job", Value::Object(job));
        let mut verified = Object::new();
        verified.insert("admission", Value::Object(admission));
        verified.insert("kind", kind);
        let mut finding = Object::new();
        let identity = if mode == "noid" {
            Value::Null
        } else {
            string(&format!("finding-{number}"))
        };
        finding.insert("id", identity);
        finding.insert("verified", Value::Object(verified));
        if mode == "oddfinding" && number == 1 {
            finding.insert("verified", Value::Array(vec![string("no object")]));
        }
        findings.push(Value::Object(finding));
    }
    if mode == "refuse" || mode == "heldnone" {
        findings.clear();
    }
    let held = HELD.contains(&mode.as_str());
    let dispatch = match mode.as_str() {
        "queued" | "heldpaused" => "paused",
        _ if held => "held",
        _ => "queue_empty",
    };
    let backlog = "backlog holds 64 failure pins without a resolved disposition at limit 64; dispose \
                   findings or raise backlog";
    let mut refusals = if held {
        vec![string(backlog)]
    } else {
        Vec::new()
    };
    if mode == "heldother" {
        refusals = vec![string("state moved during findings")];
    }
    if mode == "heldmixed" {
        refusals.push(string("state moved during findings"));
    }
    if mode == "heldomitted" {
        eprintln!("omitted refusals: 3");
    }
    let rejections = if mode == "heldrejected" {
        vec![string("a job the archive refused")]
    } else {
        Vec::new()
    };
    let refused = !refusals.is_empty();
    let mut listing = Object::new();
    listing.insert("findings", Value::Array(findings));
    listing.insert("release_blockers", Value::Array(Vec::new()));
    let mut printed = Object::new();
    printed.insert("dispatch", string(dispatch));
    printed.insert("refusals", Value::Array(refusals));
    printed.insert("rejections", Value::Array(rejections));
    printed.insert("findings", Value::Object(listing));
    say(out, &json_line(&printed));
    let mut exit = Object::new();
    exit.insert("exit", int(if refused { 4 } else { 0 }));
    say(out, &json_line(&exit));
    if refused { 4 } else { 0 }
}

fn result(out: &mut File, class: &str, reason: &str, artifact: Option<&str>) {
    let mut printed = Object::new();
    printed.insert("class", string(class));
    printed.insert("reason", string(reason));
    if let Some(artifact) = artifact {
        printed.insert("artifact", string(artifact));
    }
    say(out, &json_line(&printed));
}

fn seed(args: &[String], out: &mut File) -> i32 {
    let mode = mode_of(Path::new(option(args, "--archive")));
    if option(args, "--manifest").contains("/plants/p-hangseed/") {
        hold_until_released(&PathBuf::from(
            var("STANDIN_LOG").expect("the call log is named"),
        ));
    }
    let text = read(Path::new(option(args, "--manifest")));
    let manifest: Vec<(&str, &str)> = text
        .lines()
        .map(|line| line.split_once(" = ").expect("a manifest line holds ` = `"))
        .collect();
    let value = |key: &str| {
        manifest
            .iter()
            .rev()
            .find(|(name, _)| *name == key)
            .map_or("", |(_, value)| *value)
    };
    let root = value("root");
    if value("build") != digest(&mode)
        || value("executable") != format!("x-{mode}")
        || root == "777"
    {
        result(out, "rejected", "the manifest names another build", None);
        return 2;
    }
    if root == "665" {
        result(out, "complete", "complete: a rule failed", None);
        return 1;
    }
    if mode == "base" && root == "888" {
        say(out, "no result");
        return 4;
    }
    if mode == "base" && root == "555" {
        result(out, "complete", "complete: unsuccessful", None);
        return 0;
    }
    let failing = root == "666" || mode != "base";
    let (class, reason) = if failing {
        ("incomplete", "the run panicked")
    } else {
        ("counts", "counts: complete pass")
    };
    result(out, class, reason, Some(option(args, "--artifacts")));
    if failing { 4 } else { 0 }
}

/// `results` reads the verdict texts of the staged helper's `RESULTS` line: `CODE: "TEXT"` items.
fn results(helper: &str) -> Vec<(i32, String)> {
    let line = helper
        .lines()
        .find(|line| line.starts_with("RESULTS = {"))
        .expect("the helper holds its RESULTS line");
    let inner = line.trim_start_matches("RESULTS = {").trim_end_matches('}');
    inner
        .split(", ")
        .map(|item| {
            let (code, text) = item.split_once(": ").expect("an item holds `: `");
            (
                code.parse().expect("a code"),
                text.trim_matches('"').to_owned(),
            )
        })
        .collect()
}

fn verdict_text(results: &[(i32, String)], code: i32) -> &str {
    results
        .iter()
        .find(|(listed, _)| *listed == code)
        .map(|(_, text)| text.as_str())
        .expect("the helper words every exit it prints")
}

/// `python` answers the question to the staged helper, or runs the helper.
fn python(args: &[String], out: &mut File) -> i32 {
    if args.first().is_some_and(|arg| arg == "-B") && args.get(1).is_some_and(|arg| arg == "-c") {
        return question(&args[3..], out);
    }
    helper(args, out)
}

fn question(args: &[String], out: &mut File) -> i32 {
    let helper = read(Path::new(&args[0]));
    if let Some(log) = var("STANDIN_LOG") {
        let place = Path::new(&log)
            .parent()
            .expect("the log lies in the scratch directory");
        seen_replacement(place, "question");
    }
    if let Some(log) = var("STANDIN_QUESTION_LOG") {
        append(Path::new(&log), &format!("{}\n", args.len()));
    }
    if !helper.contains("\ndef reported(") {
        eprintln!("Traceback (most recent call last):");
        eprintln!("AttributeError: module 'staged_reproduce_test' has no attribute 'reported'");
        return 1;
    }
    let results = results(&helper);
    match args.get(1) {
        None => {
            let texts = Value::Array(vec![
                string(verdict_text(&results, 0)),
                string(verdict_text(&results, 1)),
            ]);
            say(out, &json::text(&texts));
        }
        Some(code) => {
            let code: i32 = code.parse().expect("the question names an exit");
            let mut line = String::new();
            std::io::stdin()
                .read_to_string(&mut line)
                .expect("the line is read");
            let counted =
                matches!(code, 0 | 1 | 6) && line.starts_with(verdict_text(&results, code));
            say(out, &json::text(&Value::Bool(counted)));
        }
    }
    0
}

const DETAILS: [(i32, &str); 6] = [
    (0, " in 1 attempts"),
    (1, ": reproduced on attempt 1"),
    (2, ": no test named it"),
    (3, ": the build exited 101"),
    (4, ": the test died of signal 11"),
    (6, ": attempt 1 ran past 1500 s"),
];

fn parsed(name: &str, default: &str) -> Value {
    json::parse(&var(name).unwrap_or_else(|| default.to_owned())).expect("the variable holds JSON")
}

fn listed(name: &str, test: &str) -> bool {
    matches!(parsed(name, "[]"), Value::Array(items) if items.iter().any(|item| matches!(item, Value::String(found) if found == &test)))
}

/// `helper` runs the staged helper `args[0]` in the tree it is started in.
fn helper(args: &[String], out: &mut File) -> i32 {
    let results = results(&read(Path::new(&args[0])));
    let full = |code: i32| {
        let detail = DETAILS
            .iter()
            .find(|(listed, _)| *listed == code)
            .map_or("", |(_, detail)| detail);
        format!("{}{detail}", verdict_text(&results, code))
    };
    let log =
        PathBuf::from(var("STANDIN_PROOF_LOG").expect("STANDIN_PROOF_LOG names the proof log"));
    let place = log
        .parent()
        .expect("the proof log lies in the scratch directory")
        .to_path_buf();
    seen_replacement(&place, "python3");
    let mode = read(Path::new("mode")).trim().to_owned();
    let target = std::env::var("CARGO_TARGET_DIR").ok();
    let build = std::env::var("CARGO_BUILD_BUILD_DIR").ok();
    let lock = fs::read_to_string("Cargo.lock").ok();
    // SAFETY: `getsid` and `getpid` take no pointer and cannot fail for the calling process.
    let leader = unsafe { libc::getsid(0) == libc::getpid() };
    let cwd = std::env::current_dir().expect("the rerun's directory is known");
    let text_or_null = |value: Option<String>| value.map_or(Value::Null, |value| string(&value));
    let mut record = vec![
        string(&mode),
        string(&cwd.to_string_lossy()),
        text_or_null(target.clone()),
        text_or_null(build),
        text_or_null(lock),
        Value::Bool(leader),
    ];
    record.extend(args[1..].iter().map(|arg| string(arg)));
    append(&log, &format!("{}\n", json::text(&Value::Array(record))));
    if let Some(target) = target.as_deref().filter(|target| !target.is_empty()) {
        fs::create_dir_all(target).expect("the target is made");
    }
    eprintln!("artifact: {}", option(args, "--artifacts"));
    if let Ok(lockfile) = std::env::var("CARGO_RESOLVER_LOCKFILE_PATH") {
        write(&place.join("lockfile-path"), &lockfile);
    }
    if mode == "relock" || (mode == "base" && var("STANDIN_RELOCK_HEAD").is_some()) {
        write(Path::new("Cargo.lock"), "# another resolution\n");
    }
    if mode == "unlock" {
        fs::remove_file("Cargo.lock").expect("the lockfile is removed");
    }
    if let (true, Some(target)) = (
        mode == "pintarget",
        target.as_deref().filter(|target| !target.is_empty()),
    ) {
        let pinned = Path::new(target).join("pinned");
        fs::create_dir(&pinned).expect("the pinned directory is made");
        write(&pinned.join("file"), "held");
        kestrike_tools_chmod(&pinned, 0o500);
    }
    if let Some(rewrite) = var("STANDIN_REWRITE")
        && mode == var("STANDIN_REWRITE_IN").unwrap_or_else(|| "pass".to_owned())
    {
        {
            let Ok(Value::Array(pair)) = json::parse(&rewrite) else {
                panic!("STANDIN_REWRITE holds a pair");
            };
            let [Value::String(path), Value::String(text)] = &pair[..] else {
                panic!("STANDIN_REWRITE holds a path and a text");
            };
            write(Path::new(&path.to_string()), &text.to_string());
        }
    }
    let test = option(args, "--test").to_owned();
    let end = |out: &mut File, code: i32, silent: bool, line: Option<String>| {
        if !silent {
            say(out, &line.unwrap_or_else(|| full(code)));
        }
        code
    };
    if mode == "base" {
        if listed("STANDIN_BINARY_PROOFS", &test) {
            out.write_all(b"\xff\xfe not text\n")
                .expect("the bytes are written");
            return 0;
        }
        let code = match parsed("STANDIN_HEAD_PROOFS", "{}") {
            Value::Object(codes) => number(codes.get(&test)),
            _ => 0,
        };
        let line = match parsed("STANDIN_HEAD_LINES", "{}") {
            Value::Object(lines) => match lines.get(&test) {
                Some(Value::String(line)) => Some(line.to_string()),
                _ => None,
            },
            _ => None,
        };
        let code = i32::try_from(code).expect("an exit fits");
        return end(out, code, listed("STANDIN_SILENT_PROOFS", &test), line);
    }
    if mode == "hangproof" {
        hold_until_released(&log);
    }
    let line = match mode.as_str() {
        "swappass" => Some(full(1)),
        "swapfail" => Some(full(0)),
        "trailfail" => Some(format!("{}\nthe run's last words", full(1))),
        _ => None,
    };
    let code = match mode.as_str() {
        "notlive" | "silentpass" | "swappass" => 0,
        "brokenproof" => 3,
        "watchproof" => 6,
        "rejectproof" => 2,
        "crashproof" => 4,
        _ => 1,
    };
    end(
        out,
        code,
        mode == "silentpass" || mode == "silentfail",
        line,
    )
}
