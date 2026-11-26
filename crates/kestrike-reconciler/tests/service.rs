//! The `kestrike-reconciler` binary's commands and exit codes, run as child processes over the fixture files.
//!
//! The `run` cases re-execute this test binary as the child: under [`CHILD`] its `runs::child` case calls
//! `run::serve`, the binary's own composition, over a fake store table and fake zone listings, then exits with the
//! run's exit code, so a signal and an exit code reach a real process. The fakes log every call, in order, into
//! `calls.json` before the child exits, and copy each tick's status files aside so the parent reads every tick's.

#[path = "../src/fixture.rs"]
mod fixture;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::num::{NonZeroU16, NonZeroU32};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fixture::Scratch;
use kestrike::failover::attachments::Unlisted;
use kestrike::failover::records::{Host, Namespace, Record, ShardRecord, VolumeId};
use kestrike::failover::report::Members;
use kestrike::failover::report::status::{StatusKey, StatusReader, StoreAlarm};
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::evidence::Instance;
use kestrike::failover::zone_loop::sources::{InstanceSource, ListedVolume, VolumeSource};
use kestrike::failover::zone_loop::status::Blocker;
use kestrike::net::ownership::{Shard, ShardGeneration};
use kestrike::storage::store::dynamo::{Exchange, Fault};
use kestrike::storage::store::{Item, Version, Watermark, Write};
use kestrike_reconciler::{config, run, signal};
use serde_json::{Value, json};

/// Names the scratch directory of the case that runs this binary as its child.
const CHILD: &str = "KESTRIKE_RECONCILER_CHILD";
/// The child's scenario: `steady`, `regression`, `directory`, `unpublished`, `withdrawn-unpublished`, `clock`,
/// `withdrawn-clock`, `absent`, `malformed`, `unopened`, `stopped` or `relisted`.
const SCENARIO: &str = "KESTRIKE_RECONCILER_SCENARIO";
/// The tick in whose volume listing the `steady` child waits for the parent's stop signal.
const PAUSED_TICK: usize = 3;
const NAMESPACE: Namespace = Namespace::new([7; 16]).unwrap();
/// The largest backward step of the wall clock during a run that the cases accept, in microseconds.
const WALL_STEP_US: u64 = 60_000_000;

fn binary(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kestrike-reconciler"))
        .args(args)
        .output()
        .unwrap()
}

fn command(name: &str, config: &Path) -> Output {
    binary(&[name.as_ref(), "--config".as_ref(), config.as_os_str()])
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Every call the child's fakes received, in order: `GetItem <key>` and `PutItem <key>` for the table, and the
/// describe action each listing call stands for.
type Log = Rc<RefCell<Vec<String>>>;

/// A store table holding `items`; a key in `once` is read once and then reads absent. A write is logged and
/// returns a transport fault.
struct FakeTable {
    log: Log,
    items: BTreeMap<String, Item>,
    once: Vec<String>,
}

impl Exchange for FakeTable {
    fn get(&mut self, key: &str) -> Result<Option<Item>, Fault> {
        self.log.borrow_mut().push(format!("GetItem {key}"));
        let item = self.items.get(key).cloned();
        if self.once.iter().any(|once| once == key) {
            self.items.remove(key);
        }
        Ok(item)
    }

    fn write(&mut self, key: &str, _: &Write) -> Result<Version, Fault> {
        self.log.borrow_mut().push(format!("PutItem {key}"));
        Err(Fault::Transport)
    }

    fn namespace(&self) -> Namespace {
        NAMESPACE
    }
}

struct FakeInstances(Log);

impl InstanceSource for FakeInstances {
    fn instances(&mut self, _: Zone) -> Result<Vec<Instance>, Unlisted> {
        self.0
            .borrow_mut()
            .push("DescribeInstanceStatus".to_owned());
        Ok(Vec::new())
    }
}

/// The zone's volume listing. Each call after the first copies the status files the previous tick published, as
/// `status-<tick>.json` and `sealed-<tick>`. On tick `block` it then makes a directory at the staged name of
/// `status.json`, so that tick's publish fails. On tick `pause` it writes the `paused` marker, then waits up to 60 s
/// for the stop flag, so the parent's signal arrives during that tick, and the tick goes on once the flag is set.
struct FakeVolumes {
    log: Log,
    scratch: PathBuf,
    pause: Option<usize>,
    block: Option<usize>,
    relist: bool,
}

impl VolumeSource for FakeVolumes {
    fn volumes(&mut self, _: Zone) -> Result<Vec<ListedVolume>, Unlisted> {
        let tick = {
            let mut log = self.log.borrow_mut();
            log.push("DescribeVolumes".to_owned());
            log.iter().filter(|call| *call == "DescribeVolumes").count()
        };
        if tick > 1 {
            let state = self.scratch.join("state");
            let previous = tick - 1;
            let copy = |from: &str, to: String| fs::copy(state.join(from), self.scratch.join(to));
            copy("status.json", format!("status-{previous}.json")).unwrap();
            copy("status.sealed", format!("sealed-{previous}")).unwrap();
        }
        if self.block == Some(tick) {
            fs::create_dir(self.scratch.join("state").join(".status.json.staged")).unwrap();
        }
        if self.pause == Some(tick) {
            fs::write(self.scratch.join("paused"), b"").unwrap();
            let until = Instant::now() + Duration::from_secs(60);
            while !signal::stopping() {
                assert!(Instant::now() < until, "no stop signal arrived");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        if self.relist && tick == 1 {
            let mut directory: Value = serde_json::from_str(fixture::DIRECTORY).unwrap();
            directory["zone_hold"] = json!(true);
            fs::write(self.scratch.join("directory.json"), directory.to_string()).unwrap();
        }
        Ok(Vec::new())
    }
}

/// The record of shard 1, owned by host 11 at `E = 1`, in the fake table's namespace.
fn shard_record() -> ShardRecord {
    ShardRecord {
        shard: Shard::new(1).unwrap(),
        generation: ShardGeneration::new(1).unwrap(),
        active: VolumeId::new("vol-0a").unwrap(),
        owner: Host::new(11).unwrap(),
        attempts: 1,
        spare: None,
        checkpoint: None,
        cut: 0,
        pages: NonZeroU16::new(1).unwrap(),
        page_cap: NonZeroU32::new(4096).unwrap(),
        namespace: NAMESPACE,
        ancestry: Default::default(),
        standby: None,
    }
}

fn configure(scratch: &Scratch) -> PathBuf {
    scratch.config(|config| {
        config["tick_us"] = json!(50_000);
        config["report_period_us"] = json!(50_000);
    })
}

/// `ServiceChild` calls `kill` and `wait` even during unwinding after a failed assertion.
struct ServiceChild(Child);

impl Drop for ServiceChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl ServiceChild {
    fn signal(&mut self, signal: libc::c_int) {
        assert!(self.running(), "the child exited before the signal");
        let pid = i32::try_from(self.0.id()).unwrap();
        // SAFETY: `running` found the child unreaped. As its sole reaper, `ServiceChild` keeps `pid` from being
        // reused before `kill`.
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
    }

    fn running(&mut self) -> bool {
        self.0.try_wait().unwrap().is_none()
    }
}

fn spawn(scratch: &Scratch, scenario: &str) -> ServiceChild {
    let config = configure(scratch);
    let init = command("init", &config);
    assert_eq!(init.status.code(), Some(0), "{}", stderr(&init));
    start(scratch, scenario)
}

fn start(scratch: &Scratch, scenario: &str) -> ServiceChild {
    let stdout = fs::File::create(scratch.path().join("stdout")).unwrap();
    let stderr = fs::File::create(scratch.path().join("stderr")).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "runs::child",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD, scratch.path())
        .env(SCENARIO, scenario)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap();
    ServiceChild(child)
}

/// Waits up to 60 s for `child` to exit and returns its exit code.
fn exit_code(child: &mut ServiceChild) -> Option<i32> {
    let until = Instant::now() + Duration::from_secs(60);
    while Instant::now() < until {
        if let Some(status) = child.0.try_wait().unwrap() {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the child did not exit within 60 s");
}

/// The status lines the child printed, one per tick. Under `--nocapture` libtest writes `test runs::child ... `
/// ahead of the case's first output line, so a status line is read from its `tick=` field on.
fn status_lines(scratch: &Scratch) -> Vec<String> {
    let stdout = fs::read_to_string(scratch.path().join("stdout")).unwrap_or_default();
    stdout
        .lines()
        .filter_map(|line| line.find("tick=").map(|at| line[at..].to_owned()))
        .collect()
}

/// Waits up to 60 s for a status line after the first `after` lines that `holds` accepts, and returns its index.
fn await_line(scratch: &Scratch, after: usize, holds: impl Fn(&str) -> bool) -> usize {
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        let lines = status_lines(scratch);
        if let Some(at) = (after..lines.len()).find(|&at| holds(&lines[at])) {
            return at;
        }
        assert!(Instant::now() < until, "no such status line in {lines:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn await_pause(scratch: &Scratch, child: &mut ServiceChild) {
    let paused = scratch.path().join("paused");
    let until = Instant::now() + Duration::from_secs(60);
    while !paused.exists() {
        assert!(Instant::now() < until, "the child never paused");
        assert!(child.running(), "the child exited early");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn wall_us() -> u64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    u64::try_from(since.as_micros()).unwrap()
}

/// The child's logged calls.
fn calls(scratch: &Scratch) -> (Value, Vec<String>) {
    let record = read_json(&scratch.path().join("calls.json"));
    let calls = (record["calls"].as_array().unwrap().iter())
        .map(|call| call.as_str().unwrap().to_owned())
        .collect();
    (record["exit"].clone(), calls)
}

/// `init` and the refusals every command shares.
mod init {
    use super::*;

    #[test]
    fn init_exits_0_and_a_second_init_exits_4_with_the_watermark_unchanged() {
        let scratch = Scratch::new("init-twice");
        let config = scratch.config(|_| {});
        let first = command("init", &config);
        assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
        let watermark = scratch.path().join("state").join("watermark");
        let recorded = fs::read(&watermark).unwrap();
        let second = command("init", &config);
        assert_eq!(second.status.code(), Some(4), "{}", stderr(&second));
        assert!(
            stderr(&second).contains("a watermark is already recorded"),
            "{}",
            stderr(&second)
        );
        assert_eq!(fs::read(&watermark).unwrap(), recorded);
    }

    #[test]
    fn a_refused_configuration_exits_2_naming_its_first_failed_check() {
        let scratch = Scratch::new("refused-config");
        let config = scratch.config(|config| config["tick_us"] = json!(0));
        for name in ["init", "run"] {
            let output = command(name, &config);
            assert_eq!(output.status.code(), Some(2), "{name}");
            assert!(
                stderr(&output).contains("zone configuration refused: Zero(TickUs)"),
                "{name}: {}",
                stderr(&output)
            );
        }
        assert!(!scratch.path().join("state").exists());
    }

    #[test]
    fn a_refused_command_line_exits_2() {
        let scratch = Scratch::new("command-line");
        let config = scratch.config(|_| {});
        assert_eq!(command("actuate", &config).status.code(), Some(2));
        assert_eq!(binary(&["init".as_ref()]).status.code(), Some(2));
    }
}

/// `run` through the binary, and over the fakes in the child process.
mod runs {
    use super::*;

    /// The binary checks the state directory before it opens the store table, so these runs send no request.
    #[test]
    fn run_on_an_uninitialized_state_directory_exits_4() {
        let scratch = Scratch::new("uninitialized");
        let config = scratch.config(|_| {});
        let missing = command("run", &config);
        assert_eq!(missing.status.code(), Some(4), "{}", stderr(&missing));
        fs::create_dir(scratch.path().join("state")).unwrap();
        fs::set_permissions(
            scratch.path().join("state"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let empty = command("run", &config);
        assert_eq!(empty.status.code(), Some(4), "{}", stderr(&empty));
        assert!(
            stderr(&empty).contains("no watermark is recorded"),
            "{}",
            stderr(&empty)
        );
    }

    /// The child process: runs the scenario [`SCENARIO`] names over the scratch directory [`CHILD`] names and
    /// exits with the run's code. Without [`CHILD`] it returns at once.
    #[test]
    fn child() {
        let Some(scratch) = std::env::var_os(CHILD).map(PathBuf::from) else {
            return;
        };
        let scenario = std::env::var(SCENARIO).unwrap();
        let service = config::load(&scratch.join("config.json")).unwrap();
        let log = Log::default();
        let mut table = FakeTable {
            log: log.clone(),
            items: BTreeMap::new(),
            once: Vec::new(),
        };
        let record = Item {
            version: Version::FIRST,
            value: shard_record().encode(),
        };
        table.items.insert("shard#1".to_owned(), record);
        let state = scratch.join("state");
        let mut block = None;
        let pause = match scenario.as_str() {
            "steady" => Some(PAUSED_TICK),
            "regression" => {
                table.once.push("shard#1".to_owned());
                None
            }
            "unpublished" => {
                block = Some(2);
                None
            }
            "withdrawn-unpublished" => {
                table.once.push("shard#1".to_owned());
                block = Some(2);
                None
            }
            "withdrawn-clock" => {
                table.once.push("shard#1".to_owned());
                None
            }
            "directory" | "clock" => None,
            "absent" => {
                table.items.clear();
                Some(2)
            }
            "malformed" => {
                fs::write(state.join("watermark"), b"not a watermark").unwrap();
                None
            }
            "unopened" | "stopped" | "relisted" => None,
            other => panic!("unknown scenario {other}"),
        };
        let volumes = FakeVolumes {
            log: log.clone(),
            scratch: scratch.clone(),
            pause,
            block,
            relist: scenario == "relisted",
        };
        let instances = FakeInstances(log.clone());
        let opener = || {
            log.borrow_mut().push("DescribeTable".to_owned());
            match scenario.as_str() {
                "unopened" => Err("store table: DescribeTable refused".to_owned()),
                "stopped" => {
                    // SAFETY: The `stopped` scenario requires `serve` to install the stop handler before the opener
                    // raises SIGTERM.
                    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
                    assert!(signal::stopping());
                    Ok(table)
                }
                _ => Ok(table),
            }
        };
        // The `clock` and `withdrawn-clock` scenarios fail each clock read after the second read of shard 1's
        // record, so the first failed read is the one that ends the second tick.
        let clock = || {
            let reads = (log.borrow().iter())
                .filter(|call| *call == "GetItem shard#1")
                .count();
            if scenario.ends_with("clock") && reads >= 2 {
                return Err(std::io::Error::other("no clock reading"));
            }
            signal::boot_us()
        };
        let exit = run::serve(&service, opener, instances, volumes, clock);
        let record = json!({ "exit": format!("{exit:?}"), "calls": *log.borrow() });
        fs::write(scratch.join("calls.json"), record.to_string()).unwrap();
        std::process::exit(i32::from(exit.code()));
    }

    /// SURVEY-WRITES-NOTHING over a fixed run: three ticks over a table holding one shard record read the census
    /// and both shards and list the zone each tick without one write; a second process meanwhile finds the state
    /// directory locked and exits 4; a SIGTERM or a SIGINT delivered during the third tick ends the process with
    /// exit 0 after that tick's store reads and its status, with no fourth tick; and each tick published its
    /// status.
    #[test]
    fn a_fixed_run_writes_nothing_and_exits_0_after_the_tick_a_stop_signal_interrupts() {
        for (signal, name) in [(libc::SIGTERM, "sigterm"), (libc::SIGINT, "sigint")] {
            let scratch = Scratch::new(name);
            let began_us = wall_us();
            let mut child = spawn(&scratch, "steady");
            await_pause(&scratch, &mut child);
            let second = command("init", &scratch.path().join("config.json"));
            assert_eq!(second.status.code(), Some(4), "{}", stderr(&second));
            assert!(
                stderr(&second).contains("another process holds the directory's lock"),
                "{}",
                stderr(&second)
            );
            std::thread::sleep(Duration::from_millis(100));
            child.signal(signal);
            let code = exit_code(&mut child);
            let log = fs::read_to_string(scratch.path().join("stderr")).unwrap();
            assert_eq!(code, Some(0), "{name}: {log}");
            assert!(
                log.contains(&format!("tick {PAUSED_TICK} took "))
                    && log.contains("longer than tick_us (50000 us)"),
                "{name}: {log}"
            );

            let (exit, calls) = calls(&scratch);
            assert_eq!(exit, json!("Stopped"));
            assert!(
                calls.iter().all(|call| !call.starts_with("PutItem")),
                "{calls:?}"
            );
            let listings = |action: &str| calls.iter().filter(|call| *call == action).count();
            assert_eq!(listings("DescribeVolumes"), PAUSED_TICK, "{calls:?}");
            assert_eq!(listings("DescribeInstanceStatus"), PAUSED_TICK, "{calls:?}");
            let last = calls
                .iter()
                .rposition(|call| call == "DescribeVolumes")
                .unwrap();
            let after = &calls[last + 1..];
            for read in ["GetItem standbys#1", "GetItem shard#1", "GetItem shard#2"] {
                assert!(
                    after.iter().any(|call| call == read),
                    "{name}: {read} in {after:?}"
                );
            }
            published_each_tick(&scratch, began_us);
        }
    }

    /// Each of the three ticks printed one status line and published a document and a sealed status that the
    /// status reader accepts in sequence, whose zone part counts the document's shards, blockers, sources, census
    /// and warm-up hold. Each document's `overran` holds when its duration passes the 50 ms `tick_us`, and the
    /// paused tick, which standard error names as longer than `tick_us`, reads `overran`.
    ///
    /// Each seal uses its document's `observed_at_us` as its stamp unless the wall clock moves backward, in which
    /// case the seal retains the previous stamp. Each `observed_at_us` is a wall-clock reading: it lies within
    /// [`WALL_STEP_US`] below the parent's reading before the run, a bound a reading of the loop's clock, which
    /// counts from the host's boot, stays far under.
    fn published_each_tick(scratch: &Scratch, began_us: u64) {
        let lines = status_lines(scratch);
        assert_eq!(lines.len(), PAUSED_TICK, "{lines:?}");
        for (at, line) in lines.iter().enumerate() {
            let tick = at + 1;
            assert!(
                line.starts_with(&format!("tick={tick} zone=1 shards=2 ")),
                "{line}"
            );
            assert!(line.ends_with("client=Admitted"), "{line}");
        }
        let state = scratch.path().join("state");
        let key = StatusKey::derive(&[0x99; 32]);
        let mut reader = StatusReader::default();
        let mut stamped_us = 0;
        for tick in 1..=PAUSED_TICK {
            let (document, sealed) = match tick {
                PAUSED_TICK => (state.join("status.json"), state.join("status.sealed")),
                _ => (
                    scratch.path().join(format!("status-{tick}.json")),
                    scratch.path().join(format!("sealed-{tick}")),
                ),
            };
            let document = read_json(&document);
            let sealed = fs::read(sealed).unwrap();
            let status =
                (reader.accept(&sealed, |host| (host.get() == 900).then_some(key))).unwrap();
            assert_eq!(document["format"], json!(2));
            assert_eq!(document["tick"], json!(tick));
            assert_eq!(document["client"], json!("Admitted"));
            assert_eq!(document["directory_version"], json!(1));
            let observed_us = document["observed_us"].as_u64().unwrap();
            let ended_us = document["ended_us"].as_u64().unwrap();
            assert!(ended_us >= observed_us, "{document}");
            assert_eq!(
                document["overran"],
                json!(ended_us - observed_us > 50_000),
                "{document}"
            );
            if tick == PAUSED_TICK {
                assert_eq!(document["overran"], json!(true), "{document}");
            }
            let observed_at_us = document["observed_at_us"].as_u64().unwrap();
            assert!(
                observed_at_us >= began_us.saturating_sub(WALL_STEP_US),
                "{document}"
            );
            assert_eq!(status.sealed_at_us, observed_at_us.max(stamped_us));
            stamped_us = status.sealed_at_us;
            let shards = document["shards"].as_array().unwrap();
            // Shard 1's record names volume `vol-0a`, whose record the table lacks, so the shard reads unobserved
            // from the store with a blocker, and shard 2 has no record.
            assert_eq!(
                (
                    &shards[0]["state"],
                    &shards[0]["source"],
                    &shards[0]["blocker"]
                ),
                (
                    &json!("Unobserved"),
                    &json!("Store"),
                    &json!("StoreUnavailable")
                ),
                "{document}"
            );
            assert_eq!(shards[1]["state"], json!("Initial"), "{document}");
            assert_eq!(status.sequence, tick as u64);
            let [part] = &status.zones[..] else {
                panic!("{status:?}");
            };
            assert_eq!(part.zone, Zone(1));
            assert_eq!(part.tick, tick as u64);
            assert_eq!(part.classes.iter().sum::<u32>() as usize, shards.len());
            assert_eq!(
                document["unnamed_volumes"],
                json!(part.unnamed_volumes),
                "{document}"
            );
            assert!(
                shards.iter().all(|shard| shard["closed"].is_null()),
                "{document}"
            );
            for blocker in Blocker::ALL {
                let named = json!(format!("{blocker:?}"));
                let counted = shards
                    .iter()
                    .filter(|shard| shard["blocker"] == named)
                    .count();
                assert_eq!(
                    part.blockers[blocker.position()] as usize,
                    counted,
                    "{blocker:?}"
                );
            }
            let complete = &document["complete"];
            let flags = part.flags;
            assert_eq!(
                [flags.reports, flags.instances, flags.volumes, flags.store],
                ["reports", "instances", "volumes", "store"]
                    .map(|source| complete[source] == json!(true))
            );
            assert!(
                !flags.reports,
                "the service's report source answers for no host"
            );
            let census = match part.census {
                Members::Unavailable => Value::Null,
                Members::Known { used, limit } => {
                    assert_eq!(json!(limit), document["cap"]);
                    json!(used)
                }
            };
            assert_eq!(census, document["census"]);
            assert_eq!(flags.warm_up, document["holds"]["warm_up"] == json!(true));
        }
    }

    /// Each tick rereads the directory file: a broken file leaves the next tick's shards `Unobserved` from the
    /// directory with the failed check on standard error, a successor version is admitted, and the same version
    /// with another listing reads `Unobserved` from succession with the refusal `Version` and no in-flight or
    /// verdict counts; the run goes on through all three and stops on SIGTERM with exit 0.
    #[test]
    fn each_tick_rereads_the_directory_and_reports_a_refused_one_unobserved() {
        let scratch = Scratch::new("directory");
        let mut child = spawn(&scratch, "directory");
        let first = await_line(&scratch, 0, |_| true);
        scratch.write("directory.json", "{}");
        let broken = await_line(&scratch, first + 1, |line| {
            line.contains("states=Unobserved:2")
        });
        let state = scratch.path().join("state");
        let document = read_json(&state.join("status.json"));
        assert_eq!(document["directory_version"], Value::Null, "{document}");
        let log = fs::read_to_string(scratch.path().join("stderr")).unwrap();
        assert!(
            log.contains("directory.json: missing field `format`"),
            "{log}"
        );
        scratch.directory(|directory| directory["version"] = json!(2));
        let admitted = await_line(&scratch, broken + 1, |line| {
            line.contains("states=Initial:1,Unobserved:1")
        });
        let document = read_json(&state.join("status.json"));
        assert_eq!(document["directory_version"], json!(2), "{document}");
        scratch.directory(|directory| {
            directory["version"] = json!(2);
            directory["zone_hold"] = json!(true);
        });
        await_line(&scratch, admitted + 1, |line| {
            line.contains("states=Unobserved:2")
        });
        let document = read_json(&state.join("status.json"));
        assert_eq!(
            (
                &document["shards"][0]["source"],
                &document["shards"][0]["error"]
            ),
            (&json!("Succession"), &json!("Version")),
            "{document}"
        );
        assert_eq!(document["directory_version"], Value::Null, "{document}");
        assert_eq!(document["inflight"], Value::Null, "{document}");
        assert_eq!(document["verdicts"], Value::Null, "{document}");
        child.signal(libc::SIGTERM);
        assert_eq!(exit_code(&mut child), Some(0));
        let (_, calls) = calls(&scratch);
        assert!(
            calls.iter().all(|call| !call.starts_with("PutItem")),
            "{calls:?}"
        );
    }

    /// WATERMARK: shard 1's record reads at version 1 on the first tick and absent on the second; the client
    /// withdraws under `Regression`, the second tick's status names it `ClientWithdrawn`, and the process exits 3
    /// without a write.
    #[test]
    fn a_store_regression_withdraws_the_client_and_exits_3() {
        let scratch = Scratch::new("regression");
        let mut child = spawn(&scratch, "regression");
        let code = exit_code(&mut child);
        let log = fs::read_to_string(scratch.path().join("stderr")).unwrap();
        assert_eq!(code, Some(3), "{log}");
        let (exit, calls) = calls(&scratch);
        assert_eq!(exit, json!("Withdrawn(Regression)"));
        assert!(
            calls.iter().all(|call| !call.starts_with("PutItem")),
            "{calls:?}"
        );
        let reads = calls
            .iter()
            .filter(|call| *call == "GetItem shard#1")
            .count();
        assert_eq!(reads, 2, "{calls:?}");
        assert_eq!(
            calls
                .iter()
                .filter(|call| *call == "DescribeVolumes")
                .count(),
            2
        );
        let lines = status_lines(&scratch);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].ends_with("client=Admitted"), "{}", lines[0]);
        assert!(
            lines[1].ends_with("client=ClientWithdrawn(Regression)"),
            "{}",
            lines[1]
        );
        let document = read_json(&scratch.path().join("state").join("status.json"));
        assert_eq!(document["tick"], json!(2));
        assert_eq!(document["client"], json!("ClientWithdrawn"));
        assert_eq!(document["store_alarm"], json!("Regression"));
        let key = StatusKey::derive(&[0x99; 32]);
        let mut reader = StatusReader::default();
        let mut accept = |path: PathBuf| {
            let bytes = fs::read(path).unwrap();
            reader
                .accept(&bytes, |host| (host.get() == 900).then_some(key))
                .unwrap()
        };
        let first = accept(scratch.path().join("sealed-1"));
        let second = accept(scratch.path().join("state").join("status.sealed"));
        let observed_at_us = document["observed_at_us"].as_u64().unwrap();
        assert_eq!(
            second.sealed_at_us,
            observed_at_us.max(first.sealed_at_us),
            "{document}"
        );
        for (status, tick, alarm) in [
            (first, 1, StoreAlarm::Clear),
            (second, 2, StoreAlarm::Regression),
        ] {
            assert_eq!(status.sequence, tick);
            let [part] = &status.zones[..] else {
                panic!("{status:?}");
            };
            assert_eq!((part.zone, part.tick), (Zone(1), tick));
            assert_eq!(part.store.alarm, alarm);
        }
    }

    #[test]
    fn a_status_that_fails_to_publish_exits_4_without_its_line() {
        let scratch = Scratch::new("unpublished");
        let mut child = spawn(&scratch, "unpublished");
        let code = exit_code(&mut child);
        let log = fs::read_to_string(scratch.path().join("stderr")).unwrap();
        assert_eq!(code, Some(4), "{log}");
        let exit = calls(&scratch).0;
        let exit = exit.as_str().unwrap();
        assert!(
            exit.starts_with("State(") && exit.contains("status.json: "),
            "{exit}"
        );
        assert_eq!(status_lines(&scratch).len(), 1);
        let document = read_json(&scratch.path().join("state").join("status.json"));
        assert_eq!(document["tick"], json!(1));
    }

    #[test]
    fn a_withdrawing_tick_whose_status_fails_to_publish_exits_3() {
        let scratch = Scratch::new("withdrawn-unpublished");
        let mut child = spawn(&scratch, "withdrawn-unpublished");
        let code = exit_code(&mut child);
        let log = fs::read_to_string(scratch.path().join("stderr")).unwrap();
        assert_eq!(code, Some(3), "{log}");
        assert!(
            log.contains("the tick's status did not publish: status.json: "),
            "{log}"
        );
        assert_eq!(calls(&scratch).0, json!("Withdrawn(Regression)"));
        assert_eq!(status_lines(&scratch).len(), 1);
    }

    /// A clock read that fails at the end of a tick after which the client reads admitted exits 1 without that
    /// tick's status.
    #[test]
    fn a_clock_that_fails_to_read_after_an_admitted_tick_exits_1() {
        let scratch = Scratch::new("clock");
        let mut child = spawn(&scratch, "clock");
        let code = exit_code(&mut child);
        let log = fs::read_to_string(scratch.path().join("stderr")).unwrap();
        assert_eq!(code, Some(1), "{log}");
        assert_eq!(
            calls(&scratch).0,
            json!("Open(\"the boot clock: no clock reading\")")
        );
        assert_eq!(status_lines(&scratch).len(), 1);
    }

    /// WATERMARK: a clock read that fails at the end of the withdrawing tick is named on standard error, and the
    /// process exits 3 without that tick's status.
    #[test]
    fn a_withdrawing_tick_whose_clock_fails_to_read_exits_3() {
        let scratch = Scratch::new("withdrawn-clock");
        let mut child = spawn(&scratch, "withdrawn-clock");
        let code = exit_code(&mut child);
        let log = fs::read_to_string(scratch.path().join("stderr")).unwrap();
        assert_eq!(code, Some(3), "{log}");
        assert!(
            log.contains("the tick's status did not publish: the boot clock: no clock reading"),
            "{log}"
        );
        assert_eq!(calls(&scratch).0, json!("Withdrawn(Regression)"));
        assert_eq!(status_lines(&scratch).len(), 1);
        let document = read_json(&scratch.path().join("state").join("status.json"));
        assert_eq!(document["tick"], json!(1));
    }

    #[test]
    fn a_restart_over_the_raised_watermark_withdraws_on_its_first_tick() {
        let scratch = Scratch::new("restart");
        let mut first = spawn(&scratch, "regression");
        assert_eq!(exit_code(&mut first), Some(3));
        let watermark = scratch.path().join("state").join("watermark");
        let raised = fs::read(&watermark).unwrap();
        assert_ne!(raised, Watermark::default().encode());
        let init = command("init", &scratch.path().join("config.json"));
        assert_eq!(init.status.code(), Some(4), "{}", stderr(&init));
        assert_eq!(fs::read(&watermark).unwrap(), raised);
        let mut second = start(&scratch, "absent");
        let log = || fs::read_to_string(scratch.path().join("stderr")).unwrap();
        assert_eq!(exit_code(&mut second), Some(3), "{}", log());
        let (exit, logged) = calls(&scratch);
        assert_eq!(exit, json!("Withdrawn(Regression)"));
        let ticks = logged
            .iter()
            .filter(|call| *call == "DescribeVolumes")
            .count();
        assert_eq!(ticks, 1, "{logged:?}");

        // Each run numbers its first tick 1, so the restart's seal and the first run's tick-1 document agree on
        // `tick`. The timestamps distinguish the two runs.
        let state = scratch.path().join("state");
        let earlier = read_json(&scratch.path().join("status-1.json"));
        let document = read_json(&state.join("status.json"));
        let sealed = fs::read(state.join("status.sealed")).unwrap();
        let key = StatusKey::derive(&[0x99; 32]);
        let status = StatusReader::default()
            .accept(&sealed, |host| (host.get() == 900).then_some(key))
            .unwrap();
        let [part] = &status.zones[..] else {
            panic!("{status:?}");
        };
        assert_eq!(part.tick, 1);
        assert_eq!(document["tick"], json!(1));
        assert_eq!(earlier["tick"], json!(1));
        assert_eq!(json!(status.sealed_at_us), document["observed_at_us"]);
        assert_ne!(json!(status.sealed_at_us), earlier["observed_at_us"]);

        let control = Scratch::new("restart-control");
        let mut child = spawn(&control, "absent");
        await_pause(&control, &mut child);
        child.signal(libc::SIGTERM);
        assert_eq!(exit_code(&mut child), Some(0));
        assert_eq!(calls(&control).0, json!("Stopped"));
    }

    #[test]
    fn a_watermark_that_fails_to_load_exits_4_before_the_table_opens() {
        let scratch = Scratch::new("malformed");
        let mut child = spawn(&scratch, "malformed");
        assert_eq!(exit_code(&mut child), Some(4));
        let (exit, calls) = calls(&scratch);
        assert!(exit.as_str().unwrap().starts_with("State("), "{exit}");
        assert!(calls.is_empty(), "{calls:?}");
    }

    #[test]
    fn a_table_that_fails_to_open_exits_1_before_any_read() {
        let scratch = Scratch::new("unopened");
        let mut child = spawn(&scratch, "unopened");
        assert_eq!(exit_code(&mut child), Some(1));
        let (exit, calls) = calls(&scratch);
        assert_eq!(exit, json!("Open(\"store table: DescribeTable refused\")"));
        assert_eq!(calls, ["DescribeTable"]);
    }

    /// DIRECTORY-SUCCESSION: a reread with another listing at the admitted `version` is refused on every later
    /// tick. Standard error names the refusal `Version`, and the refused ticks list nothing and read no store
    /// record.
    #[test]
    fn a_relisted_directory_at_the_admitted_version_is_named_on_standard_error_and_reads_nothing() {
        let scratch = Scratch::new("relisted");
        let mut child = spawn(&scratch, "relisted");
        let log = || fs::read_to_string(scratch.path().join("stderr")).unwrap();
        let refusal = format!(
            "directory file {}: refused by succession (Version) over the directory last admitted",
            scratch.path().join("directory.json").display()
        );
        let until = Instant::now() + Duration::from_secs(60);
        while !log().contains(&refusal) {
            assert!(Instant::now() < until, "no refusal line: {}", log());
            assert!(child.running(), "the child exited early: {}", log());
            std::thread::sleep(Duration::from_millis(10));
        }
        child.signal(libc::SIGTERM);
        assert_eq!(exit_code(&mut child), Some(0), "{}", log());
        let (exit, calls) = calls(&scratch);
        assert_eq!(exit, json!("Stopped"));
        for call in [
            "DescribeVolumes",
            "GetItem standbys#1",
            "GetItem shard#1",
            "GetItem shard#2",
        ] {
            let count = calls.iter().filter(|logged| *logged == call).count();
            assert_eq!(count, 1, "{call} in {calls:?}");
        }
    }

    #[test]
    fn a_stop_before_the_first_tick_exits_0_without_a_tick() {
        let scratch = Scratch::new("stopped");
        let mut child = spawn(&scratch, "stopped");
        assert_eq!(exit_code(&mut child), Some(0));
        let (exit, calls) = calls(&scratch);
        assert_eq!(exit, json!("Stopped"));
        assert_eq!(calls, ["DescribeTable"]);
    }
}

/// A diagnostic or a status line that `/dev/full` refuses leaves the exit code the command chose.
#[test]
fn exit_codes_stand_when_standard_output_and_error_refuse_writes() {
    let scratch = Scratch::new("full");
    let config = scratch.config(|_| {});
    let full = || {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap()
    };
    let run = |name: &str| {
        Command::new(env!("CARGO_BIN_EXE_kestrike-reconciler"))
            .args([name.as_ref(), "--config".as_ref(), config.as_os_str()])
            .stdout(full())
            .stderr(full())
            .status()
            .unwrap()
            .code()
    };
    assert_eq!(run("init"), Some(0));
    assert!(scratch.path().join("state").join("watermark").exists());
    assert_eq!(run("init"), Some(4));
    assert_eq!(run("actuate"), Some(2));
}
