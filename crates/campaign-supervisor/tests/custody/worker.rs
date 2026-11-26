use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use campaign_supervisor::record::Started;
use campaign_supervisor::store::{Name, View};

pub(super) fn worker(plan: &Path) -> ExitCode {
    let action = fs::read_to_string(plan.join("action")).unwrap();
    let state = View::open(&plan.join("state")).expect("state view");
    let group = fs::read_to_string("/proc/self/cgroup").expect("membership");
    let path = group
        .trim()
        .strip_prefix("0::")
        .expect("unified membership");
    let probe_dir = if action.starts_with("admission") {
        let probes = state
            .open_dir(state.root(), &Name::new("probes").unwrap())
            .unwrap()
            .unwrap();
        Some(
            state
                .open_dir(
                    &probes,
                    &Name::new(path.rsplit('/').next().unwrap()).unwrap(),
                )
                .unwrap()
                .unwrap(),
        )
    } else {
        None
    };
    let attempt_dir = if action == "campaign-pass" {
        let (job, number) = path.rsplit('/').next().unwrap().rsplit_once('-').unwrap();
        let attempts = crate::sharded::open_shard(&state, "attempts", job);
        let job = state
            .open_dir(&attempts, &Name::new(job).unwrap())
            .unwrap()
            .unwrap();
        Some(
            state
                .open_dir(&job, &Name::new(number).unwrap())
                .unwrap()
                .unwrap(),
        )
    } else {
        None
    };
    let started = state
        .read_record::<Started>(
            attempt_dir
                .as_ref()
                .or(probe_dir.as_ref())
                .unwrap_or(state.root()),
            &Name::new("started").unwrap(),
        )
        .expect("started verifies")
        .expect("started precedes worker effects");

    assert_eq!(
        format!("/sys/fs/cgroup{path}"),
        started.record().cgroup.as_str()
    );
    let status = fs::read_to_string("/proc/self/status").expect("status");
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .unwrap()
        .trim();
    assert_eq!(mask, "0000000000000000");
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let after_name = stat.rsplit_once(')').unwrap().1;
    let group: u32 = after_name
        .split_whitespace()
        .nth(2)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        group,
        std::process::id(),
        "exec starts its own process group"
    );
    fs::write(plan.join("seen"), format!("{path}\n{mask}\n")).unwrap();
    let stall = Duration::from_secs(
        std::env::var("CAMPAIGN_CUSTODY_STALL_SECONDS")
            .unwrap()
            .parse()
            .unwrap(),
    );
    if action.starts_with("admission") {
        if action == "admission-stall" {
            std::thread::sleep(stall);
        }
        if action == "admission-controlled" {
            let deadline = Instant::now() + stall;
            while !plan.join("finish").exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        print!("{}", include_str!("../../testdata/admission-listing.txt"));
        return if action == "admission-failed" {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        };
    }
    if action == "campaign-pass" {
        let args: Vec<_> = std::env::args().skip(1).collect();
        let value = |flag: &str| {
            args.iter()
                .position(|arg| arg == flag)
                .map(|at| &args[at + 1])
        };
        if args == ["--capabilities"] {
            print!("{}", include_str!("../../testdata/admission-listing.txt"));
        } else {
            if let Some(output) = value("--bundle") {
                let manifest = fs::read_to_string(value("--manifest").unwrap()).unwrap();
                let canonical = manifest
                    .lines()
                    .filter(|line| !line.starts_with("cpu = "))
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                let mut bundle = vec![0; 48];
                bundle[0] = 1;
                for (index, chunk) in canonical.as_bytes().chunks(43).enumerate() {
                    let mut record = [0; 48];
                    record[0] = 2;
                    record[1] = 1;
                    record[2..4].copy_from_slice(&u16::try_from(index).unwrap().to_le_bytes());
                    record[4] = u8::try_from(chunk.len()).unwrap();
                    record[5..5 + chunk.len()].copy_from_slice(chunk);
                    bundle.extend_from_slice(&record);
                }
                for _ in 0..2 {
                    let mut record = [0; 48];
                    record[0] = 4;
                    bundle.extend_from_slice(&record);
                }
                fs::write(output, bundle).unwrap();
            }
            print!("{}", include_str!("../../testdata/counting.summary"));
        }
        return ExitCode::SUCCESS;
    }
    match action.as_str() {
        "escapee" | "escapee-stall" => {
            assert!(
                Command::new("/usr/bin/setsid")
                    .arg("--fork")
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg("echo $$ > \"$1/escapee-ready\"; sleep \"$2\"; echo late > \"$1/late\"")
                    .arg("custody-escapee")
                    .arg(plan)
                    .arg(stall.as_secs().to_string())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("session escapee")
                    .success()
            );
            let deadline = Instant::now() + Duration::from_secs(1);
            while !plan.join("escapee-ready").exists() {
                assert!(Instant::now() < deadline, "escapee ready bound");
                std::thread::sleep(Duration::from_millis(1));
            }
            if action == "escapee-stall" {
                std::thread::sleep(stall);
            }
        }
        "burst" => {
            let mut children = Vec::new();
            loop {
                match Command::new("/bin/sleep").arg("20").spawn() {
                    Ok(child) => children.push(child),
                    Err(error) => {
                        assert!(!children.is_empty(), "fork burst reached children");
                        fs::write(
                            plan.join("fork-refused"),
                            format!("{}:{error}", children.len()),
                        )
                        .unwrap();
                        break;
                    }
                }
                assert!(children.len() < 32, "pids limit must stop the burst");
            }
        }
        "oom" => {
            println!("{}", include_str!("../../testdata/listing.txt"));
            std::io::stdout().flush().unwrap();
            let mut memory = vec![0u8; 512 << 20];
            for byte in memory.iter_mut().step_by(4096) {
                *byte = 1;
            }
            std::hint::black_box(&memory);
            panic!("memory limit must kill the attempt");
        }
        "fsize" => {
            fs::write(plan.join("oversize"), vec![0; 8192]).unwrap();
            panic!("file size limit must stop the write");
        }
        "cpu" => {
            let deadline = Instant::now() + Duration::from_millis(200);
            while Instant::now() < deadline {
                std::hint::black_box(123u64.wrapping_mul(456));
            }
        }
        "interrupt" | "interrupt-int" => {
            let pid = std::env::var("CAMPAIGN_CUSTODY_CONTROLLER").unwrap();
            assert!(
                Command::new("/bin/kill")
                    .args([
                        if action == "interrupt" {
                            "-TERM"
                        } else {
                            "-INT"
                        },
                        &pid
                    ])
                    .status()
                    .unwrap()
                    .success()
            );
            std::thread::sleep(Duration::from_secs(20));
        }
        "stall" => std::thread::sleep(stall),
        "normal" => {}
        _ => panic!("unknown worker action"),
    }
    print!("{}", include_str!("../../testdata/listing.txt"));
    ExitCode::SUCCESS
}
