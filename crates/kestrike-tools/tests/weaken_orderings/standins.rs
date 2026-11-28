//! A POSIX `sh` wrapper starts this test executable as `cargo` or as the GenMC lane. It passes the child's
//! arguments after `--`, gives the real standard output to the stand-in as descriptor 3, and sends
//! libtest's own lines to `/dev/null`.
//!
//! A stand-in acts out the mode that the JSON plan at `STUB_PLAN` gives its test or case: the `clean` mode
//! while the scoped files hold the digest that the run's first call wrote to `STUB_PLAN.seen`, the
//! `planted` mode once they differ. `cargo` appends each call's arguments, directory and shaping
//! environment as a JSON line to `STUB_PLAN.env` and each test it runs to `STUB_PLAN.log`; the lane
//! appends each call to `STUB_PLAN.lane`. A stand-in that panics writes its role, its arguments and the
//! panic to `STUB_PLAN.failed`, which fails the case.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kestrike_tools::genmc::case::check_line;
use kestrike_tools::json::{self, Object, Text, Value};
use kestrike_tools::orderings::check::{CATALOG, GENMC, family_kernel};
use kestrike_tools::orderings::sources::kernel_texts;
use kestrike_tools::python::hexdigest;
use regex::Regex;

pub const ROLE: &str = "WEAKEN_STANDIN";
const ROLE_TEST: &str = "weaken_orderings::standins::role";
pub const GENMC_BINARY: &str = "/genmc/build/bin/genmc";

pub fn wrapper(role: &str) -> String {
    let exe = std::env::current_exe().expect("the test executable is known");
    format!(
        "#!/bin/sh\n{ROLE}={role}\nexport {ROLE}\nexec '{}' --exact {ROLE_TEST} --nocapture \
         --test-threads 1 -- \"$@\" 3>&1 1>/dev/null\n",
        exe.display()
    )
}

pub fn suffixed(plan: &Path, suffix: &str) -> PathBuf {
    let mut name = plan.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[test]
fn role() {
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let args: Vec<String> = std::env::args()
        .skip_while(|arg| arg != "--")
        .skip(1)
        .collect();
    let plan = PathBuf::from(std::env::var_os("STUB_PLAN").expect("the stand-in has a plan"));
    let failed = suffixed(&plan, ".failed");
    let shown = format!("{role:?} {args:?}");
    std::panic::set_hook(Box::new(move |info| {
        append(&failed, &format!("{shown}: {info}\n"));
    }));
    // SAFETY: the wrapper opens descriptor 3 as the caller's standard output, and nothing else in this
    // process owns it.
    let mut out = unsafe { File::from_raw_fd(3) };
    let code = match role.to_str() {
        Some("cargo") => cargo(&args, &plan, &mut out),
        Some("lane") => lane(&args, &plan),
        other => panic!("no stand-in plays {other:?}"),
    };
    let _ = out.flush();
    std::process::exit(code);
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn write(path: &Path, text: &str) {
    fs::write(path, text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

fn append(path: &Path, text: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    file.write_all(text.as_bytes())
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

fn plan_mode(plan: &Path, test: &str, phase: &str) -> Option<String> {
    let plan = json::parse(&read(plan)).expect("the plan is JSON");
    match &plan {
        Value::Object(plan) => match plan.get(test) {
            Some(Value::Object(modes)) => match modes.get(phase) {
                Some(Value::String(mode)) => Some(mode.to_string()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn plan_field(plan: &Path, test: &str, field: &str) -> Option<String> {
    plan_mode(plan, test, field)
}

pub fn scoped_files(copy: &Path) -> Vec<String> {
    let catalog = json::parse(&read(&copy.join(CATALOG))).expect("the catalog is JSON");
    let Value::Object(catalog) = catalog else {
        panic!("the catalog is an object");
    };
    match catalog.get("files") {
        Some(Value::Array(files)) => files
            .iter()
            .map(|file| match file {
                Value::String(file) => file.to_string(),
                _ => panic!("a scoped file is a string"),
            })
            .collect(),
        _ => panic!("the catalog lists its files"),
    }
}

fn phase(plan: &Path, files: &[String]) -> &'static str {
    let mut bytes = Vec::new();
    for name in files {
        match fs::read(name) {
            Ok(read) => bytes.extend(read),
            Err(error) => bytes.extend(format!("{name}: {error}").into_bytes()),
        }
    }
    let state = hexdigest(&bytes);
    let seen = suffixed(plan, ".seen");
    if !seen.exists() {
        write(&seen, &state);
    }
    if read(&seen) == state {
        "clean"
    } else {
        "planted"
    }
}

fn shown(name: &str) -> String {
    var(name).unwrap_or_else(|| "None".to_owned())
}

fn strings(items: &[String]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| Value::String(Text::from(item.as_str())))
            .collect(),
    )
}

fn code_of(name: &str) -> i32 {
    var(name).map_or(0, |code| code.parse().expect("an exit code"))
}

fn cargo(args: &[String], plan: &Path, out: &mut File) -> i32 {
    let cwd = std::env::current_dir().expect("the directory is known");
    let shaping = Regex::new(
        r"^(RUSTC\w*|RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_\w+|CARGO_BUILD_\w+|CARGO_TARGET_\w+|CARGO_PROFILE_\w+|LOOM_\w+)$",
    )
    .expect("the pattern compiles");
    let mut env = Object::new();
    for (name, value) in std::env::vars() {
        if shaping.is_match(&name) {
            env.insert(name.as_str(), Value::String(Text::from(value.as_str())));
        }
    }
    let mut call = Object::new();
    call.insert("args", strings(args));
    call.insert(
        "cwd",
        Value::String(Text::from(cwd.to_string_lossy().as_ref())),
    );
    call.insert("env", Value::Object(env));
    append(
        &suffixed(plan, ".env"),
        &format!("{}\n", json::line(&Value::Object(call))),
    );
    let has = |word: &str| args.iter().any(|arg| arg == word);
    if has("tree") {
        let code = code_of("STUB_TREE_EXIT");
        if code == 0 {
            write(Path::new("Cargo.lock"), "stub lock\n");
        }
        let at = args.iter().position(|arg| arg == "-i").expect("an -i");
        let line = if args[at + 1] == "loom" {
            var("STUB_LOOM").unwrap_or_else(|| format!("loom v{}", shown("LOOM")))
        } else {
            String::new()
        };
        writeln!(out, "{line}").expect("written");
        return code;
    }
    if has("config") {
        let kernels = cwd.ends_with("verification/genmc/packages/kernels");
        let name = if kernels {
            "STUB_CONFIG_KERNELS"
        } else {
            "STUB_CONFIG"
        };
        writeln!(out, "{}", var(name).unwrap_or_else(|| "{}".to_owned())).expect("written");
        eprintln!("{}", var("STUB_CONFIG_ERR").unwrap_or_default());
        return code_of("STUB_CONFIG_EXIT");
    }
    let at = args
        .iter()
        .position(|arg| arg == "--release")
        .expect("a --release");
    loom_test(&args[at + 1], plan, out)
}

static STOPPED: OnceLock<CString> = OnceLock::new();
static TWICE: AtomicBool = AtomicBool::new(false);

extern "C" fn stopped(_: libc::c_int) {
    if TWICE.load(Ordering::SeqCst) {
        // SAFETY: `getppid` and `kill` take plain values and are async-signal-safe.
        unsafe { libc::kill(libc::getppid(), libc::SIGHUP) };
    }
    if let Some(path) = STOPPED.get() {
        // SAFETY: `open`, `close` and `_exit` are async-signal-safe, and the path outlives the call.
        unsafe {
            let fd = libc::open(
                path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            );
            if fd >= 0 {
                libc::write(fd, b"1".as_ptr().cast(), 1);
                libc::close(fd);
            }
        }
    }
    // SAFETY: `_exit` ends the process without running any handler of this process.
    unsafe { libc::_exit(143) };
}

fn sleep_until_stopped(plan: &Path, twice: bool) {
    TWICE.store(twice, Ordering::SeqCst);
    let path = CString::new(suffixed(plan, ".stopped").as_os_str().as_bytes()).expect("no NUL");
    let _ = STOPPED.set(path);
    // SAFETY: `stopped` is an `extern "C"` handler that calls only async-signal-safe functions.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            stopped as extern "C" fn(libc::c_int) as libc::sighandler_t,
        )
    };
    write(&suffixed(plan, ".sleeping"), "1");
    std::thread::sleep(Duration::from_secs(60));
}

fn loom_test(test: &str, plan: &Path, out: &mut File) -> i32 {
    let files = scoped_files(Path::new("."));
    let phase = phase(plan, &files);
    let mut mode = plan_mode(plan, test, phase).unwrap_or_else(|| "pass".to_owned());
    let mut loom: Vec<String> = std::env::vars()
        .map(|(name, _)| name)
        .filter(|name| name.starts_with("LOOM_"))
        .collect();
    loom.sort();
    let listed: Vec<String> = loom.iter().map(|name| format!("'{name}'")).collect();
    let watched = fs::read(&files[3]).unwrap_or_default();
    append(
        &suffixed(plan, ".log"),
        &format!(
            "{test} {phase} {} {} [{}] {} {}/{} {}\n",
            shown("RUSTFLAGS"),
            shown("CARGO_TARGET_DIR"),
            listed.join(", "),
            shown("CARGO_ENCODED_RUSTFLAGS"),
            shown("CARGO_TERM_COLOR"),
            shown("CARGO_TERM_QUIET"),
            hexdigest(&watched)
        ),
    );
    if mode.starts_with("sleep") {
        sleep_until_stopped(plan, mode == "sleep-twice");
    }
    if let Some(rewritten) = mode.strip_prefix("rewrite:") {
        rewrite(plan, rewritten);
        mode = "pass".to_owned();
    }
    let (other, own) = (Path::new(&files[0]), Path::new(&files[3]));
    match mode.as_str() {
        "drift" | "drift-own" => {
            let target = if mode == "drift" { other } else { own };
            let mut file = OpenOptions::new().append(true).open(target).expect("opens");
            file.write_all(b"// drift\n").expect("written");
            mode = "pass".to_owned();
        }
        "link" => {
            let twin = PathBuf::from(format!("{}.twin", files[0]));
            fs::write(&twin, fs::read(other).expect("reads")).expect("written");
            fs::remove_file(other).expect("removed");
            symlink(twin.file_name().expect("a name"), other).expect("linked");
            mode = "pass".to_owned();
        }
        "gone" | "dangling" | "loop" | "dir-own" | "gone-other" | "dir-other" => {
            let target = if mode.ends_with("-other") { other } else { own };
            fs::remove_file(target).expect("removed");
            if mode == "dangling" {
                symlink("absent", target).expect("linked");
            } else if mode == "loop" {
                symlink(target.file_name().expect("a name"), target).expect("linked");
            } else if mode.starts_with("dir") {
                fs::create_dir(target).expect("made");
            }
            mode = "pass".to_owned();
        }
        "unreadable" | "unreadable-other" => {
            let target = if mode.ends_with("-other") { other } else { own };
            fs::set_permissions(target, fs::Permissions::from_mode(0o000)).expect("changed");
            mode = "pass".to_owned();
        }
        _ => {}
    }
    test_output(test, &mode, plan, out)
}

fn test_output(test: &str, mode: &str, plan: &Path, out: &mut File) -> i32 {
    let mut say = |line: &str| writeln!(out, "{line}").expect("written");
    if mode != "norebuild" {
        say("   Compiling kestrike v0.1.0 (copy)");
    }
    if mode == "build" {
        say("error[E0308]: mismatched types");
        return 101;
    }
    if mode == "crash" {
        say("running 1 test");
        return 101;
    }
    say(if mode == "none" {
        "running 0 tests"
    } else {
        "running 1 test"
    });
    match mode {
        "pass" | "norebuild" => {
            say(&format!(
                "test {test} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out"
            ));
            0
        }
        "none" => {
            say("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out");
            0
        }
        "ignored" => {
            say(&format!(
                "test {test} ... ignored\n\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 9 filtered out"
            ));
            0
        }
        _ => {
            let at = plan_field(plan, test, "at").unwrap_or_else(|| "model.rs:1".to_owned());
            let message = mode.strip_prefix("fail:").unwrap_or(mode);
            say(&format!(
                "test {test} ... FAILED\nthread '{test}' panicked at {at}:21:\n{message}\n\
                 test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out"
            ));
            101
        }
    }
}

pub fn positive(executions: u32) -> String {
    [
        "GenMC v0.19.0 (LLVM 22.1.8)",
        "*** Compilation complete.",
        "*** Transformation complete.",
        "*** Verification complete.",
        "No errors were detected.",
        &format!("Number of complete executions explored: {executions}"),
        "Total wall-clock time: 0.49s",
        "",
    ]
    .join("\n")
}

pub fn violation(line: usize, file: &str) -> String {
    [
        "GenMC v0.19.0 (LLVM 22.1.8)",
        "*** Compilation complete.",
        "*** Transformation complete.",
        "Error: Safety violation!",
        "Event (0, 4) in graph:",
        "<-1, 0>:",
        &format!("\t(0, 4): ERROR {file}:{line}"),
        "*** Verification unsuccesful.",
        "Number of complete executions explored: 0",
        "Total wall-clock time: 0.44s",
        "",
    ]
    .join("\n")
}

pub fn graph_of(text: &str) -> String {
    let event = Regex::new(r"(?m)^\s*\((\d+), (\d+)\): (.*)$").expect("the pattern compiles");
    let nodes: Vec<String> = event
        .captures_iter(text)
        .map(|found| {
            let (thread, step, label) = (&found[1], &found[2], &found[3]);
            let label = match label.strip_prefix("ERROR ") {
                Some(rest) => format!("ERROR <FONT COLOR=\"gray\"> {rest}</FONT>"),
                None => label.to_owned(),
            };
            format!("\t\"({thread}, {step})\" [label=<{label}>, tooltip=\"({thread}, {step})\"]")
        })
        .collect();
    format!("strict digraph {{\n{}\n}}\n", nodes.join("\n"))
}

fn declared(copy: &Path) -> Value {
    json::parse(&read(&copy.join(GENMC))).expect("the declaration is JSON")
}

fn member<'v>(value: &'v Value, key: &str) -> &'v Value {
    match value {
        Value::Object(object) => object.get(key).unwrap_or_else(|| panic!("no member {key}")),
        _ => panic!("no object holds {key}"),
    }
}

fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.to_string(),
        _ => panic!("{value:?} is no string"),
    }
}

/// `violation_of` is the output of a GenMC run of `case` in `copy` that reports `failure` at the line of
/// the `check!` that carries it in the case family's kernel.
pub fn violation_of(copy: &Path, case: &str, failure: &str) -> String {
    let declared = declared(copy);
    let package = PathBuf::from(text_of(member(&declared, "package")));
    let kernels: BTreeMap<String, String> =
        kernel_texts(&copy.join(&package)).expect("kernels read");
    let (file, _) = family_kernel(&Text::from(case), &kernels).expect("the case has a kernel");
    let mut kernel = Object::new();
    kernel.insert("file", Value::String(Text::from(file)));
    let line = check_line(
        copy,
        &Value::Object(kernel),
        &Value::String(Text::from(failure)),
    )
    .expect("the failure is one check's message");
    let name = Path::new(file)
        .file_name()
        .expect("a name")
        .to_string_lossy();
    violation(line, &name)
}

fn rewrite(plan: &Path, rewritten: &str) {
    let (case, failure) = rewritten.split_once(':').expect("a case and a failure");
    let lanes = fs::read_to_string(suffixed(plan, ".lane")).expect("a lane ran");
    let last = lanes.lines().last().expect("a lane call");
    let evidence = PathBuf::from(last.split(' ').nth(1).expect("an evidence directory"));
    let text = violation_of(Path::new("."), case, failure);
    write(&evidence.join(format!("genmc-{case}.txt")), &text);
    write(
        &evidence.join(format!("genmc-{case}.dot")),
        &graph_of(&text),
    );
}

fn lane(args: &[String], plan: &Path) -> i32 {
    let copy = std::env::current_dir().expect("the directory is known");
    let cases = &args[2..];
    let evidence = PathBuf::from(std::env::var_os("EVIDENCE").expect("an evidence directory"));
    fs::create_dir_all(&evidence).expect("made");
    let files = scoped_files(&copy);
    let phase = phase(plan, &files);
    append(
        &suffixed(plan, ".lane"),
        &format!(
            "{phase} {} {}/{} {}\n",
            evidence.display(),
            shown("CARGO_TERM_COLOR"),
            shown("CARGO_TERM_QUIET"),
            args.join(" ")
        ),
    );
    let mut binary = Object::new();
    binary.insert("path", Value::String(Text::from(GENMC_BINARY)));
    let mut rustc = Object::new();
    rustc.insert("name", Value::String(Text::from("nightly-2026-07-27")));
    rustc.insert("toolchain", Value::String(Text::from("/toolchain")));
    let mut record = Object::new();
    record.insert("binary", Value::Object(binary));
    record.insert("rustc", Value::Object(rustc));
    write(
        &evidence.join("identity.json"),
        &json::line(&Value::Object(record)),
    );
    write(&evidence.join("cargo-config.json"), "{}");
    let declared = declared(&copy);
    let package = PathBuf::from(text_of(member(&declared, "package")));
    let options: Vec<String> = match member(&declared, "options") {
        Value::Array(options) => options.iter().map(text_of).collect(),
        _ => panic!("the options are a list"),
    };
    for case in cases {
        let mode = plan_mode(plan, case, phase).unwrap_or_else(|| "positive".to_owned());
        if mode == "abort" {
            write(
                &evidence.join(format!("check-{case}.txt")),
                "error: could not compile `genmc-kernels`\n",
            );
            return 1;
        }
        let parent = package.parent().expect("the package has a parent");
        let manifest = copy
            .join(parent)
            .join(format!("run-{case}"))
            .join("Cargo.toml");
        let graph = evidence.join(format!("genmc-{case}.dot"));
        let mut argv = vec![GENMC_BINARY.to_owned()];
        argv.extend(options.iter().cloned());
        argv.push(format!("--dump-error-graph={}", graph.display()));
        argv.push(manifest.display().to_string());
        write(
            &evidence.join(format!("genmc-{case}.argv")),
            &format!("{}\n", argv.join("\n")),
        );
        write(
            &evidence.join(format!("genmc-{case}.env")),
            &format!(
                "CASE={case}\nRUSTUP_TOOLCHAIN=nightly-2026-07-27\nRUSTC=/toolchain/bin/rustc\n\
                 RUSTC_WRAPPER=\nRUSTC_WORKSPACE_WRAPPER=\n"
            ),
        );
        let rebuilt = if mode == "norebuild" {
            ""
        } else {
            "    Checking genmc-kernels v0.0.0\n"
        };
        write(&evidence.join(format!("check-{case}.txt")), rebuilt);
        let (text, code) = match mode.strip_prefix("violation:") {
            Some(failure) => (violation_of(&copy, case, failure), 42),
            None => (positive(if phase == "clean" { 5 } else { 3 }), 0),
        };
        write(&evidence.join(format!("genmc-{case}.txt")), &text);
        let exit = if mode == "badexit" {
            "x\n".to_owned()
        } else {
            format!("{code}\n")
        };
        write(&evidence.join(format!("genmc-{case}.exit")), &exit);
        write(&graph, &graph_of(&text));
    }
    0
}
