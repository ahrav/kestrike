//! The fake `campaign`, `aws`, `git` and `cargo` the host cases put on
//! `PATH`. Each reads its case's control files, logs each call as a JSON
//! line, and keeps the bucket as a directory tree.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const CASE: &str = "SIM_HOST_FAKE";
pub const NAMES: [&str; 4] = ["campaign", "aws", "git", "cargo"];

pub const BACKLOG: &str = "backlog holds 64 failure pins without a resolved disposition at limit 64; dispose findings or raise backlog";

static TERMINATED: AtomicBool = AtomicBool::new(false);

extern "C" fn terminated(_: libc::c_int) {
    TERMINATED.store(true, Ordering::SeqCst);
}

/// Milliseconds since the Unix epoch, the clock of a record's `written`.
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_millis() as u64
}

pub fn now_ms() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid `timespec` for the call to fill.
    let read = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    assert_eq!(read, 0, "the monotonic clock reads");
    u64::try_from(now.tv_sec).unwrap_or(0) * 1000
        + u64::try_from(now.tv_nsec).unwrap_or(0) / 1_000_000
}

fn log(case: &Path, entry: &Value) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(case.join("log"))
        .expect("the fake's log opens");
    file.write_all(format!("{entry}\n").as_bytes())
        .expect("the fake's log is written");
}

fn word(case: &Path, name: &str, index: usize) -> Option<String> {
    fs::read_to_string(case.join(name))
        .ok()
        .and_then(|text| text.split_whitespace().nth(index).map(str::to_owned))
}

fn scripted(case: &Path, name: &str, index: usize, default: u64) -> u64 {
    word(case, name, index)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn ordinal(case: &Path, command: &str) -> usize {
    let path = case.join(format!("{command}.count"));
    let count: usize = fs::read_to_string(&path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0);
    fs::write(&path, (count + 1).to_string()).expect("the count is written");
    count
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn complete_lines(path: &Path) -> u64 {
    fs::read(path).map_or(0, |bytes| {
        bytes.iter().filter(|byte| **byte == b'\n').count() as u64
    })
}

/// The build record envelope `campaign sim archive` writes for a checkout
/// at `head`, with the provenance in the case's `archive.provenance` when
/// that file is present and a clean checkout of `head` otherwise.
pub fn build_record(case: &Path, head: &str) -> String {
    let provenance = fs::read_to_string(case.join("archive.provenance"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .unwrap_or_else(|| json!({"revision": head, "dirty": false, "untracked": 0}));
    json!({"format": 1, "kind": "build", "record": {"provenance": provenance},
           "sha256": "0".repeat(64)})
    .to_string()
}

pub fn head(case: &Path) -> String {
    fs::read_to_string(case.join("git.head"))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn checked_out(case: &Path) -> String {
    fs::read_to_string(case.join("checkout.head"))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

pub fn fake(name: &str) -> ExitCode {
    let case = PathBuf::from(std::env::var_os(CASE).expect("the fake runs inside a case"));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match name {
        "campaign" => campaign(&case, &args),
        "aws" => aws(&case, &args),
        "git" => git(&case, &args),
        _ => cargo(&case, &args),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(255))
}

fn campaign(case: &Path, args: &[String]) -> u64 {
    let handler = terminated as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: `terminated` only stores to an atomic.
    let installed = unsafe { libc::signal(libc::SIGTERM, handler) };
    assert_ne!(
        installed,
        libc::SIG_ERR,
        "the fake's SIGTERM handler installs"
    );
    let command = args.first().cloned().unwrap_or_default();
    match (command.as_str(), args.get(1).map(String::as_str)) {
        ("sweep-status" | "findings", _) => return report(case, &command, args),
        ("sim", Some("archive")) => return archive(case, args),
        ("sim", Some("capabilities")) => return capabilities(case, args),
        _ => {}
    }
    let index = ordinal(case, &command);
    let code = scripted(case, &format!("{command}.codes"), index, 0);
    log(
        case,
        &json!({"event": "start", "command": command, "index": index, "t": now_ms(),
                "args": args, "program": std::env::args().next(),
                "pid": std::process::id(), "parent": std::os::unix::process::parent_id()}),
    );
    let root = flag(args, "--root").map(PathBuf::from);
    let code = match (command.as_str(), root) {
        ("sweep", Some(root)) => sweep(case, args, &root, index, code),
        ("confirm", Some(root)) => confirm(case, &root, index, code),
        _ => 2,
    };
    let terminated = TERMINATED.load(Ordering::SeqCst);
    if terminated {
        log(
            case,
            &json!({"event": "signal", "command": command, "index": index, "t": now_ms()}),
        );
        let linger = scripted(case, &format!("{command}.linger"), index, 0);
        std::thread::sleep(Duration::from_millis(linger));
    }
    log(
        case,
        &json!({"event": "exit", "command": command, "index": index, "t": now_ms(),
                "code": code, "terminated": terminated}),
    );
    code
}

fn report(case: &Path, command: &str, args: &[String]) -> u64 {
    if command == "sweep-status" {
        if case.join("sweep-status.fail").exists() {
            eprintln!("campaign sweep-status: a scripted failure");
            return 4;
        }
        let root = PathBuf::from(flag(args, "--root").unwrap_or_default());
        let runs: u64 = fs::read_to_string(root.join("runs"))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0);
        let campaign = root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        println!(
            "{}",
            json!({"campaign": campaign, "runs": runs, "pass": runs,
                   "suspects": complete_lines(&root.join("suspects.jsonl"))})
        );
        return 0;
    }
    let state = PathBuf::from(flag(args, "--state").unwrap_or_default());
    if !state.is_dir() || case.join("findings.fail").exists() {
        eprintln!("campaign findings: no state directory");
        return 2;
    }
    match fs::read_to_string(case.join("findings.json")) {
        Ok(text) => print!("{text}"),
        Err(_) => print!(r#"{{"findings":[],"release_blockers":[]}}"#),
    }
    0
}

fn archive(case: &Path, args: &[String]) -> u64 {
    let Some(output) = flag(args, "--output") else {
        return 2;
    };
    let output = PathBuf::from(output);
    let head = checked_out(case);
    let code = scripted(case, "archive.codes", ordinal(case, "archive"), 0);
    if code != 0 {
        log(
            case,
            &json!({"event": "archive-failed", "command": "campaign", "t": now_ms(), "code": code}),
        );
        eprintln!("campaign sim archive: a scripted failure with code {code}");
        return code;
    }
    log(
        case,
        &json!({"event": "archive", "command": "campaign", "t": now_ms(), "head": head,
                "opt_level": std::env::var("CARGO_PROFILE_DEV_OPT_LEVEL").ok()}),
    );
    fs::create_dir_all(&output).expect("the archive directory");
    fs::write(output.join("build"), build_record(case, &head)).expect("the build record");
    fs::write(output.join("worker"), "worker").expect("the worker");
    0
}

fn capabilities(case: &Path, args: &[String]) -> u64 {
    let archive = PathBuf::from(flag(args, "--archive").unwrap_or_default());
    log(
        case,
        &json!({"event": "capabilities", "command": "campaign", "t": now_ms(),
                "archive": archive}),
    );
    if fs::read(archive.join("worker")).ok().as_deref() != Some(b"worker".as_slice()) {
        eprintln!("campaign sim capabilities: the archive's worker differs from its record");
        return 2;
    }
    println!("{{\"capabilities\":\"profile: a\"}}");
    0
}

fn wait_until(until: Instant, step: Duration, done: impl Fn() -> bool) {
    while Instant::now() < until && !TERMINATED.load(Ordering::SeqCst) && !done() {
        std::thread::sleep(step);
    }
}

fn wait(until: Instant) {
    wait_until(until, Duration::from_millis(20), || false);
}

fn append(root: &Path, text: &str) {
    if text.is_empty() {
        return;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("suspects.jsonl"))
        .expect("the suspect list opens")
        .write_all(text.as_bytes())
        .expect("a suspect line is written");
}

fn lines(campaign: &str, index: usize, count: u64) -> String {
    (0..count)
        .map(|run| {
            format!(
                "{}\n",
                json!({"campaign": campaign, "run": run, "sweep": index})
            )
        })
        .collect()
}

fn sweep(case: &Path, args: &[String], root: &Path, index: usize, code: u64) -> u64 {
    if (2..=4).contains(&code) {
        eprintln!("campaign sweep: a scripted failure with code {code}");
        return code;
    }
    let campaign = flag(args, "--campaign").unwrap_or_default();
    fs::create_dir_all(root).expect("the root is created");
    let bound = root.join("sweep.json");
    let binding = format!(
        "{campaign} {}",
        args.iter()
            .enumerate()
            .filter(|(position, _)| *position > 0 && args[position - 1] == "--set")
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    match fs::read_to_string(&bound) {
        Ok(text) if text != binding => {
            eprintln!("campaign sweep: the root holds {text}");
            return 2;
        }
        Ok(_) => {}
        Err(_) => fs::write(&bound, &binding).expect("sweep.json is written"),
    }
    let runs: u64 = fs::read_to_string(root.join("runs"))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0);
    fs::write(root.join("runs"), (runs + 10).to_string()).expect("the runs are written");
    append(
        root,
        &lines(&campaign, index, scripted(case, "sweep.suspects", index, 0)),
    );
    if scripted(case, "sweep.torn", index, 0) == 1 {
        append(root, "{\"torn\":");
    }
    let cpu = scripted(case, "sweep.cpu", index, 0);
    if let Some(cgroup) = flag(args, "--cgroup-root") {
        let group = Path::new(&cgroup).join("sweep");
        fs::create_dir_all(&group).expect("the sweep group is created");
        let stat = group.join("cpu.stat");
        let used: u64 = fs::read_to_string(&stat)
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("usage_usec "))
                    .and_then(|value| value.trim().parse().ok())
            })
            .unwrap_or(0);
        let text = if scripted(case, "sweep.cpu_broken", index, 0) == 1 {
            "user_usec 0\n".to_owned()
        } else {
            format!("usage_usec {}\nuser_usec 0\n", used + cpu)
        };
        fs::write(&stat, text).expect("cpu.stat is written");
    }
    let length = flag(args, "--for")
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    if scripted(case, "sweep.after_confirm", index, 0) == 1 {
        wait_until(
            Instant::now() + Duration::from_secs(60),
            Duration::from_millis(1),
            || {
                fs::read_to_string(case.join("log"))
                    .unwrap_or_default()
                    .contains("\"command\":\"confirm\",\"event\":\"exit\"")
            },
        );
    } else {
        wait(Instant::now() + Duration::from_secs(length));
    }
    std::thread::sleep(Duration::from_millis(scripted(
        case,
        "sweep.late_delay",
        index,
        0,
    )));
    append(
        root,
        &lines(&campaign, index, scripted(case, "sweep.late", index, 0)),
    );
    code
}

fn findings(case: &Path) -> serde_json::Value {
    let bytes = scripted(case, "confirm.findings_bytes", 0, 0);
    json!({"hint": "raise backlog", "rows": ["f".repeat(usize::try_from(bytes).unwrap_or(0))]})
}

fn confirm(case: &Path, root: &Path, index: usize, code: u64) -> u64 {
    let window = complete_lines(&root.join("suspects.jsonl"));
    let pause = scripted(case, "confirm.ms", index, 0);
    wait(Instant::now() + Duration::from_millis(pause));
    let backlog = code == 4 && scripted(case, "confirm.backlog", index, 0) == 1;
    if code == 0 || backlog {
        let dir = root.join("confirm");
        fs::create_dir_all(dir.join("state")).expect("the confirm directory is created");
        fs::write(dir.join("confirmed"), window.to_string()).expect("confirmed is written");
    }
    if code == 0 {
        let dispatch =
            word(case, "confirm.dispatch", index).unwrap_or_else(|| "queue_empty".into());
        let filler = if case.join("confirm.big").exists() {
            "x".repeat(200_000)
        } else {
            String::new()
        };
        println!(
            "{}",
            json!({"dispatch": dispatch, "refusals": [], "rejections": [],
                   "findings": {"filler": filler, "listing": findings(case)}})
        );
        if scripted(case, "confirm.block_state", index, 0) == 1 {
            let state = root
                .parent()
                .and_then(Path::parent)
                .expect("the root is under the state directory");
            fs::create_dir(state.join(".state.json.staged"))
                .expect("a directory blocks the state replacement");
        }
    } else if backlog {
        println!(
            "{}",
            json!({"dispatch": "held", "refusals": [BACKLOG], "rejections": [],
                   "findings": findings(case)})
        );
        eprintln!("campaign confirm: {BACKLOG}");
        if scripted(case, "confirm.lose_err", index, 0) == 1 {
            let state = root
                .parent()
                .and_then(Path::parent)
                .expect("the root is under the state directory");
            fs::remove_file(state.join("logs/confirm.err")).expect("the error log is removed");
        }
    } else {
        eprintln!("campaign confirm: a scripted hold with code {code}; raise backlog");
    }
    code
}

pub fn encode64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let indices = [
            group[0] >> 2,
            ((group[0] & 0x03) << 4) | (group[1] >> 4),
            ((group[1] & 0x0f) << 2) | (group[2] >> 6),
            group[2] & 0x3f,
        ];
        for (position, index) in indices.iter().enumerate() {
            if position <= chunk.len() {
                text.push(char::from(ALPHABET[usize::from(*index)]));
            } else {
                text.push('=');
            }
        }
    }
    text
}

pub fn digest64(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest: [u8; 32] = sha2::Sha256::digest(bytes).into();
    encode64(&digest)
}

pub fn checksum_path(bucket: &Path, key: &str) -> PathBuf {
    bucket.join(".checksums").join(key)
}

fn aws(case: &Path, args: &[String]) -> u64 {
    let op = args
        .iter()
        .position(|arg| arg == "s3api")
        .and_then(|index| args.get(index + 1))
        .cloned()
        .unwrap_or_default();
    let key = flag(args, "--key").unwrap_or_default();
    log(
        case,
        &json!({"event": "call", "command": "aws", "op": op, "key": key, "t": now_ms(),
                "unix_ms": unix_ms(),
                "once": args.iter().any(|arg| arg == "--if-none-match"),
                "range": flag(args, "--range"), "max_items": flag(args, "--max-items"),
                "prefix": flag(args, "--prefix"), "if_match": flag(args, "--if-match"),
                "token": flag(args, "--starting-token")}),
    );
    // `aws.hang.prefix` and `aws.fail.prefix` hold a key prefix whose
    // calls hang or fail while every other key answers, and
    // `aws.hang.list-prefix` and `aws.fail.list-prefix` do the same for the
    // listings of a prefix under theirs; a hung call logs
    // a `hang` event before it sleeps. `aws.nowrite.prefix` makes a
    // get-object under its prefix exit 0 and write no file, and
    // `aws.nonregular.prefix` makes one exit 0 with a directory at its
    // output path.
    let listed = flag(args, "--prefix");
    let under = |name: &str| {
        let (control, named) = match &listed {
            Some(listed) => (name.replace(".prefix", ".list-prefix"), listed),
            None => (name.to_owned(), &key),
        };
        fs::read_to_string(case.join(control))
            .is_ok_and(|prefix| !prefix.trim().is_empty() && named.starts_with(prefix.trim()))
    };
    if case.join("aws.hang").exists() || under("aws.hang.prefix") {
        log(
            case,
            &json!({"event": "hang", "command": "aws", "op": op, "key": key, "t": now_ms()}),
        );
        std::thread::sleep(Duration::from_secs(600));
    }
    let failed = [
        "aws.fail".to_owned(),
        format!("aws.fail.{op}"),
        format!("aws.fail.{op}.{}", key.replace('/', "_")),
    ];
    if failed.iter().any(|name| case.join(name).exists()) || under("aws.fail.prefix") {
        eprintln!(
            "\nCould not connect to the endpoint URL: \"https://sims.s3.amazonaws.com/{key}\""
        );
        return 255;
    }
    let bucket = case.join("bucket");
    let object = bucket.join(&key);
    let checksum = checksum_path(&bucket, &key);
    match op.as_str() {
        "put-object" => {
            if let Some(delay) =
                fs::read_to_string(case.join(format!("aws.delay.{}", key.replace('/', "_"))))
                    .ok()
                    .and_then(|delay| delay.trim().parse().ok())
            {
                std::thread::sleep(Duration::from_millis(delay));
            }
            let once = args.iter().any(|arg| arg == "--if-none-match");
            // A create-once put under the prefix in `aws.collide.prefix`
            // finds another object at its key, which the fake stores first;
            // the control then leaves, so later puts proceed. One under
            // `aws.echo.prefix` finds its own body stored, as a retry past a
            // lost reply does.
            let collide = case.join("aws.collide.prefix");
            let planted = if once && under("aws.collide.prefix") {
                let _ = fs::remove_file(&collide);
                Some(b"{\"another\": true}".to_vec())
            } else if once && under("aws.echo.prefix") {
                Some(fs::read(flag(args, "--body").unwrap_or_default()).expect("the body reads"))
            } else {
                None
            };
            if let Some(planted) = planted
                && !object.exists()
            {
                for path in [&object, &checksum] {
                    fs::create_dir_all(path.parent().expect("a parent")).expect("the prefix");
                }
                fs::write(&object, &planted).expect("the planted object");
                fs::write(&checksum, digest64(&planted)).expect("its checksum");
            }
            if once && object.exists() {
                eprintln!(
                    "\naws: [ERROR]: An error occurred (PreconditionFailed) when calling the PutObject operation: At least one of the pre-conditions you specified did not hold"
                );
                return 254;
            }
            let body = fs::read(flag(args, "--body").unwrap_or_default()).expect("the body reads");
            for path in [&object, &checksum] {
                fs::create_dir_all(path.parent().expect("a parent")).expect("the prefix");
            }
            let staged = object.with_extension("staged");
            fs::write(&staged, &body).expect("the object is written");
            fs::rename(&staged, &object).expect("the object is placed");
            if flag(args, "--checksum-algorithm").as_deref() == Some("SHA256") {
                fs::write(&checksum, digest64(&body)).expect("the checksum is recorded");
            } else {
                let _ = fs::remove_file(&checksum);
            }
            // Puts under the key prefix in `aws.stall.prefix` store the
            // object, then pause for 600 seconds to simulate a lost reply.
            if under("aws.stall.prefix") {
                std::thread::sleep(Duration::from_secs(600));
            }
            println!("{}", json!({"ChecksumSHA256": digest64(&body)}));
            0
        }
        "get-object" => {
            let delays = [
                "aws.delay".to_owned(),
                format!("aws.delay.{}", key.replace('/', "_")),
            ];
            for delay in delays.iter().filter_map(|name| {
                fs::read_to_string(case.join(name))
                    .ok()
                    .and_then(|delay| delay.trim().parse().ok())
            }) {
                std::thread::sleep(Duration::from_millis(delay));
            }
            if under("aws.nowrite.prefix") {
                println!("{{}}");
                return 0;
            }
            if under("aws.nonregular.prefix") {
                fs::create_dir(args.last().expect("an output file")).expect("a directory");
                println!("{{}}");
                return 0;
            }
            let Ok(mut body) = fs::read(&object) else {
                eprintln!(
                    "\naws: [ERROR]: An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist."
                );
                return 254;
            };
            if let Some(etag) = flag(args, "--if-match")
                && etag != format!("\"{}\"", sim_host::file::sha256(&body))
            {
                eprintln!(
                    "\naws: [ERROR]: An error occurred (PreconditionFailed) when calling the GetObject operation: At least one of the pre-conditions you specified did not hold"
                );
                return 254;
            }
            if flag(args, "--checksum-mode").as_deref() == Some("ENABLED")
                && let Ok(digest) = fs::read_to_string(&checksum)
                && digest != digest64(&body)
            {
                eprintln!(
                    "\naws: [ERROR]: Expected checksum {digest} did not match calculated checksum"
                );
                return 255;
            }
            if let Some(range) = flag(args, "--range") {
                let end: usize = range
                    .strip_prefix("bytes=0-")
                    .and_then(|end| end.parse().ok())
                    .expect("a range from byte 0");
                if body.is_empty() {
                    eprintln!(
                        "\nAn error occurred (InvalidRange) when calling the GetObject operation: The requested range is not satisfiable"
                    );
                    return 254;
                }
                body.truncate(end.saturating_add(1));
            }
            let output = args.last().expect("an output file");
            fs::write(output, body).expect("the download is written");
            println!("{{}}");
            0
        }
        "head-object" => {
            let Ok(body) = fs::read(&object) else {
                eprintln!(
                    "\nAn error occurred (404) when calling the HeadObject operation: Not Found"
                );
                return 254;
            };
            let length = if case.join("aws.huge").exists() && key.starts_with("builds/") {
                u64::MAX / 4
            } else {
                body.len() as u64
            };
            let mut head = json!({"ContentLength": length,
                                  "ETag": format!("\"{}\"", sim_host::file::sha256(&body))});
            if flag(args, "--checksum-mode").as_deref() == Some("ENABLED")
                && let Ok(digest) = fs::read_to_string(&checksum)
            {
                let digest = if case
                    .join(format!("aws.badsum.{}", key.replace('/', "_")))
                    .exists()
                {
                    digest64(b"other bytes")
                } else {
                    digest
                };
                head["ChecksumSHA256"] = json!(digest);
                head["ChecksumType"] = json!("FULL_OBJECT");
            }
            println!("{head}");
            0
        }
        "list-objects-v2" => {
            let token = flag(args, "--starting-token").unwrap_or_default();
            let prefix = flag(args, "--prefix").unwrap_or_default();
            let canned = format!("aws.listing.{}{token}", prefix.replace('/', "_"));
            if let Ok(page) = fs::read_to_string(case.join(canned)) {
                print!("{page}");
                return 0;
            }
            let mut keys = Vec::new();
            let mut pending = vec![bucket.clone()];
            while let Some(dir) = pending.pop() {
                for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        pending.push(path);
                    } else {
                        let key = path
                            .strip_prefix(&bucket)
                            .expect("under the bucket")
                            .to_string_lossy()
                            .into_owned();
                        if key.starts_with(&prefix) && !key.ends_with(".staged") {
                            keys.push(key);
                        }
                    }
                }
            }
            keys.sort();
            if case.join("aws.reverse").exists() {
                keys.reverse();
            }
            if keys.is_empty() {
                return 0;
            }
            let page = fs::read_to_string(case.join("aws.page"))
                .ok()
                .and_then(|page| page.trim().parse().ok())
                .into_iter()
                .chain(flag(args, "--max-items").and_then(|items| items.parse().ok()))
                .min()
                .unwrap_or(usize::MAX);
            let start: usize = flag(args, "--starting-token")
                .map_or(0, |token| token.parse().expect("a token the fake printed"));
            let end = start.saturating_add(page).min(keys.len());
            let contents: Vec<Value> = keys[start..end]
                .iter()
                .map(|key| {
                    let body = fs::read(bucket.join(key)).expect("an object");
                    json!({"Key": key, "Size": body.len(),
                           "ETag": format!("\"{}\"", sim_host::file::sha256(&body))})
                })
                .collect();
            let mut listing = json!({"Contents": contents});
            if end < keys.len() {
                listing["NextToken"] = json!(end.to_string());
            }
            println!("{listing}");
            0
        }
        _ => 252,
    }
}

fn git(case: &Path, args: &[String]) -> u64 {
    log(
        case,
        &json!({"event": "call", "command": "git", "args": args, "t": now_ms(),
                "cwd": std::env::current_dir().ok()}),
    );
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        // The remote's head is `git.head`; only a fetch of `main` from
        // `origin` moves `origin/main`, kept in `git.fetched`.
        ["fetch", "--quiet", "origin", "main"] => {
            if case.join("git.fetch.fail").exists() {
                log(
                    case,
                    &json!({"event": "fetch-failed", "command": "git", "t": now_ms()}),
                );
                eprintln!("fatal: unable to access the remote");
                return 128;
            }
            fs::write(case.join("git.fetched"), head(case)).expect("the fetched head");
        }
        ["fetch", ..] => {
            eprintln!("fatal: the fake fetches only main from origin");
            return 128;
        }
        ["rev-parse", "origin/main"] => match fs::read_to_string(case.join("git.fetched")) {
            Ok(fetched) => println!("{}", fetched.trim()),
            Err(_) => {
                eprintln!("fatal: ambiguous argument 'origin/main': unknown revision");
                return 128;
            }
        },
        ["rev-parse", ..] => {
            eprintln!("fatal: the fake resolves only origin/main");
            return 128;
        }
        ["status", ..] => print!(
            "{}",
            fs::read_to_string(case.join("git.dirty")).unwrap_or_default()
        ),
        ["checkout", ..] => {
            let target = args.last().expect("a commit");
            fs::write(case.join("checkout.head"), target).expect("the checkout");
        }
        _ => {}
    }
    0
}

fn cargo(case: &Path, args: &[String]) -> u64 {
    let index = ordinal(case, "cargo");
    log(
        case,
        &json!({"event": "call", "command": "cargo", "args": args, "t": now_ms(),
                "head": checked_out(case)}),
    );
    let code = scripted(case, "cargo.codes", index, 0);
    if code != 0 {
        eprintln!("error: could not compile `campaign-supervisor`");
        return code;
    }
    if case.join("cargo.empty").exists() {
        return 0;
    }
    let release = std::env::current_dir()
        .expect("a directory")
        .join("target/release");
    fs::create_dir_all(&release).expect("the target directory");
    let program = release.join("campaign");
    let _ = fs::remove_file(&program);
    std::os::unix::fs::symlink(std::env::current_exe().expect("this executable"), &program)
        .expect("the built campaign");
    0
}
