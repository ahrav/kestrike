//! Replays the binder model's traces against two binder processes that
//! share one fixture tree, and compares the model's state after every
//! action with what the processes and the tree show.
//!
//! Each bind and release of a trace runs [`Binder`] in a fresh child of the
//! test executable, connected to this supervisor through
//! [`replay_control`]. The child stops before and after every step of the
//! model, so the supervisor runs one action at a time: it requires the
//! child's next step to be the trace's next action of that binder, on the
//! action's device, lets the step run or refuses it as the action's input
//! says, and reads the result. `crash` sends `SIGKILL` to a child stopped
//! after a step and confirms the signal; a later action of that binder
//! starts a fresh process.
//!
//! Compared after every action, `init` included: both owners' lock holders
//! and each device lock's holder, read from the lock lines of each child's
//! `/proc/<pid>/fdinfo`; each open group guard, by the descriptor the child
//! reports, checked in `/proc/<pid>/fd`; each owner's record, as its file's
//! presence, the devices its raw lines name and the devices
//! [`Mappings::read`] gives; every device's driver and override in the
//! fixture's sysfs; the ENI's network state; until a call ends, the devices
//! its bind wrote an override for and the devices its release wrote, from
//! the child's journal of kernel writes, against the devices the release's
//! record named, and the count, modulo four, of network commands its restore
//! has run; and the outcome the action reported, empty for an action that
//! reports none.
//! The model's step counter and request sets are its own bookkeeping; the
//! order of the children's steps stands for them.
//!
//! After every action the census also holds: each device on `vfio-pci` is
//! named by exactly one owner's readable record.
//!
//! The committed traces replay under plain `cargo test`. Each records its
//! recipe and the digest of `quint/binder.qnt` under `#meta.binder`, written
//! by `python3 quint/binder_check.py --quint quint --output DIR`; the `quint`
//! lane regenerates them, requires the committed files to equal them and
//! replays them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::binder::{BindRequest, Binder, EniRequest, VFIO, mappings_path};
use super::binder_tests::{ALLOWLISTED, PEERS};
use super::fixture::{
    BDF, ENI, ENI_BDF, ENI_NETDEV, FakeKernel, FakeMetadata, Fixture, Journal, Live, VOLUME,
    host_at,
};
use super::mappings::Mappings;
use super::replay_control::{self, Command, ROLLED_BACK, Report};
use crate::exact_child::{self, ExactChild, Outcome};

/// The child test's own ID, which the supervisor runs by exact name.
const CHILD: &str = "bind::replay_tests::the_supervised_binder_child_runs_its_call";

/// The environment the supervisor hands each child.
const ROOT: &str = "KESTRIKE_BIND_REPLAY_ROOT";
const OWNER: &str = "KESTRIKE_BIND_REPLAY_OWNER";
const MODE: &str = "KESTRIKE_BIND_REPLAY_MODE";
const REQUEST: &str = "KESTRIKE_BIND_REPLAY_REQUEST";
const SOCKET: &str = "KESTRIKE_BIND_REPLAY_SOCKET";
const JOURNAL: &str = "KESTRIKE_BIND_REPLAY_JOURNAL";

/// The wait for one report of a child. A child reaches its next step in
/// under one second in an unoptimized build on a development host.
const DEADLINE: Duration = Duration::from_secs(30);

/// The model's devices: 0 is the controller and 1 the ENI.
const DEVICES: [&str; 2] = [BDF, ENI_BDF];
const KERNEL_DRIVERS: [&str; 2] = ["nvme", "ena"];

/// The commands a restore of the ENI's network state runs, in order.
const NETWORK_COMMANDS: [&str; 4] = [
    "ip link set dev if6 mtu 9001",
    "ip link set dev if6 up",
    "ip addr replace 10.0.1.5/24 brd 10.0.1.255 metric 1003 dev if6",
    "ip route replace 10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003 dev if6",
];
const ADDRESSES: &str = "10.0.1.5/24 brd 10.0.1.255 metric 1003";
const ROUTES: &str = "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003";

const MODEL: &[u8] = include_bytes!("../../../../quint/binder.qnt");
const CAMPAIGN: &str = include_str!("replay_fixtures/campaign.itf.json");
const LOCK_GAP_PREFIX: &str = include_str!("replay_fixtures/lock_gap_prefix.itf.json");
const FIXTURES: [(&str, &str); 2] = [("campaign", CAMPAIGN), ("lock_gap_prefix", LOCK_GAP_PREFIX)];

/// The campaign's kills, each confirmed as a `SIGKILL` death.
const CAMPAIGN_DEATHS: usize = 6;
/// Every action of the model; the campaign runs each.
const ACTIONS: [&str; 31] = [
    "bindOwner",
    "bindPreflight",
    "bindDeviceLock",
    "consultRecords",
    "resolveHops",
    "publish",
    "secondCapture",
    "setOverride",
    "unbind",
    "vfioBind",
    "bindReturn",
    "crash",
    "liveOwnerRefusal",
    "releaseOwner",
    "readRecord",
    "releaseDeviceLock",
    "releaseConsult",
    "groupGuard",
    "restoreUnbind",
    "restoreOverride",
    "restoreBind",
    "restoreOriginalOverride",
    "networkBatch",
    "unlink",
    "releaseReturn",
    "rollbackUnbind",
    "rollbackOverride",
    "rollbackBind",
    "rollbackOriginalOverride",
    "rollbackNetworkBatch",
    "rollbackReturn",
];
/// Every outcome of the model but `guard-refused`; the campaign reaches each.
const CAMPAIGN_OUTCOMES: [&str; 13] = [
    "preflight-refused",
    "contention-refused",
    "other-owner-refused",
    "published",
    "second-capture-refused",
    "driver-refused",
    "bound",
    "crash-before-publish",
    "crash-after-publish",
    "fresh-release-refuses-missing",
    "fresh-release-restores",
    "rolled-back",
    "live-owner-refused",
];

/// Runs the bind or release its environment names against the supervisor's
/// fixture tree, stopping at every step, and reports the call's result.
/// Outside a child it does nothing.
#[test]
fn the_supervised_binder_child_runs_its_call() {
    if !exact_child::is_child(CHILD) {
        return;
    }
    exact_child::report(&exact_child::entered(CHILD));
    let env = |key: &str| std::env::var(key).unwrap_or_else(|_| panic!("{key} is set"));
    let root = PathBuf::from(env(ROOT));
    let owner: usize = env(OWNER).parse().unwrap();
    let mode = env(MODE);
    let requested: Vec<usize> = env(REQUEST)
        .split(',')
        .filter(|device| !device.is_empty())
        .map(|device| device.parse().unwrap())
        .collect();
    replay_control::connect(root.clone(), &env(SOCKET), &mode);
    let host = host_at(&root);
    let kernel = FakeKernel::new(&host);
    let state_dir = root.join(format!("owner-{owner}"));
    kernel.journal.replace(Some(Journal {
        log: OpenOptions::new()
            .create(true)
            .append(true)
            .open(env(JOURNAL))
            .unwrap(),
        record: mappings_path(&state_dir),
    }));
    for (hop, mac) in [
        ("10.0.1.9", "0a:00:00:00:01:09"),
        ("10.0.1.1", "0a:00:00:00:01:01"),
    ] {
        kernel
            .answers
            .borrow_mut()
            .insert(hop.parse().unwrap(), mac);
    }
    let binder = Binder {
        host,
        kernel,
        state_dir,
    };
    let others = [root.join(format!("owner-{}", 1 - owner))];
    let result = match mode.as_str() {
        "bind" => {
            let manifest = Fixture::manifest_of(&binder.host);
            let metadata = FakeMetadata::new();
            binder
                .bind(&BindRequest {
                    volume: requested.contains(&0).then_some(VOLUME),
                    eni: requested.contains(&1).then_some(EniRequest {
                        id: ENI,
                        peers: &PEERS,
                        metadata: &metadata,
                    }),
                    posture: ALLOWLISTED,
                    wc: &manifest,
                    others: &others,
                })
                .map(drop)
        }
        "release" => binder.release(&others),
        _ => panic!("unknown mode {mode}"),
    };
    // A call that returns after its last step stops once more, so the
    // supervisor can kill it before it exits.
    let rolled_back = replay_control::mode() == "rollback";
    if result.is_ok() || rolled_back {
        let phase = match (rolled_back, mode.as_str()) {
            (true, _) => "rollbackReturn",
            (false, "bind") => "bindReturn",
            _ => "releaseReturn",
        };
        replay_control::before(phase, "");
        replay_control::after(phase, "", true);
    }
    replay_control::returned(&format!("{result:?}"));
}

/// One supervised child: its connection, whether it waits for `advance`,
/// the call it runs, its journal of kernel writes and the group guards its
/// last report named.
struct Process {
    child: ExactChild,
    stream: BufReader<UnixStream>,
    stopped: bool,
    mode: &'static str,
    journal: PathBuf,
    guards: BTreeMap<String, (i32, u64, u64)>,
}

impl Process {
    fn report(&mut self) -> Result<Report, String> {
        let mut line = String::new();
        match self.stream.read_line(&mut line) {
            Ok(read) if read > 0 => serde_json::from_str(&line).map_err(|error| error.to_string()),
            Ok(_) => Err("the child closed its connection".into()),
            Err(error) => Err(format!("no report from the child: {error}")),
        }
    }

    fn send(&mut self, verb: &str, accept: bool) -> Result<(), String> {
        let command = Command {
            verb: verb.to_owned(),
            accept,
        };
        let mut line = serde_json::to_string(&command).unwrap();
        line.push('\n');
        self.stream
            .get_mut()
            .write_all(line.as_bytes())
            .map_err(|error| format!("the child takes no {verb}: {error}"))
    }

    fn advance(&mut self) -> Result<(), String> {
        if std::mem::take(&mut self.stopped) {
            self.send("advance", true)?;
        }
        Ok(())
    }
}

/// What a replay ran: its actions, the outcomes it reached and the kills
/// it confirmed.
#[derive(Default)]
struct Tally {
    actions: BTreeSet<String>,
    outcomes: BTreeSet<String>,
    deaths: usize,
}

/// The supervisor of one trace: the fixture tree, each binder's live
/// child, and what the children's steps and journals have shown.
struct Replay {
    processes: [Option<Process>; 2],
    fixture: Fixture,
    requests: [Vec<usize>; 2],
    moved: [BTreeSet<usize>; 2],
    released_names: [BTreeSet<usize>; 2],
    release_writes: BTreeSet<(usize, usize)>,
    network_part: [usize; 2],
    outcome: String,
    spawned: usize,
    tally: Tally,
}

/// One action of a trace, as its state's `last` records it.
struct Action {
    act: String,
    binder: usize,
    device: Option<usize>,
    requested: Vec<usize>,
    accept: bool,
}

impl Action {
    fn of(last: &Value) -> Result<Self, String> {
        let number = |key: &str| last[key].as_i64().ok_or(format!("last.{key}"));
        let requested = last["requested"].as_array().ok_or("last.requested")?;
        Ok(Self {
            act: last["act"].as_str().ok_or("last.act")?.to_owned(),
            binder: usize::try_from(number("binder")?).map_err(|_| "last.binder")?,
            device: usize::try_from(number("device")?).ok(),
            requested: requested
                .iter()
                .map(|device| device.as_u64().map(|device| device as usize))
                .collect::<Option<_>>()
                .ok_or("last.requested")?,
            accept: last["accept"].as_bool().ok_or("last.accept")?,
        })
    }

    /// The action as its recipe writes it.
    fn recipe(&self) -> String {
        let Self {
            act,
            binder,
            accept,
            ..
        } = self;
        match (act.as_str(), self.device) {
            ("bindOwner", _) => {
                let requested: Vec<String> = self.requested.iter().map(usize::to_string).collect();
                format!("bindOwner({binder}, Set({}))", requested.join(", "))
            }
            ("bindPreflight", _) => format!("bindPreflight({binder}, {accept})"),
            ("secondCapture" | "setOverride" | "unbind" | "vfioBind" | "groupGuard", Some(d)) => {
                format!("{act}({binder}, {d}, {accept})")
            }
            (_, Some(device)) => format!("{act}({binder}, {device})"),
            (_, None) => format!("{act}({binder})"),
        }
    }
}

impl Replay {
    fn new() -> Self {
        let fixture = Fixture::new(4096).unlisted();
        for owner in 0..2 {
            fs::create_dir(fixture.root.join(format!("owner-{owner}"))).unwrap();
        }
        let net = fixture.host.sys.join("class/net").join(ENI_NETDEV);
        fs::write(net.join("addresses"), ADDRESSES).unwrap();
        fs::write(net.join("routes"), ROUTES).unwrap();
        Self {
            processes: [None, None],
            fixture,
            requests: Default::default(),
            moved: Default::default(),
            released_names: Default::default(),
            release_writes: BTreeSet::new(),
            network_part: [0, 0],
            outcome: String::new(),
            spawned: 0,
            tally: Tally::default(),
        }
    }

    fn state_dir(&self, owner: usize) -> PathBuf {
        self.fixture.root.join(format!("owner-{owner}"))
    }

    /// Starts `owner`'s child for `mode` and waits for its connection.
    fn start(&mut self, owner: usize, mode: &'static str) -> Result<(), String> {
        if self.processes[owner].is_some() {
            return Err(format!("binder {owner} still runs its last call"));
        }
        self.spawned += 1;
        let socket = self.fixture.root.join(format!("socket-{}", self.spawned));
        let journal = self.fixture.root.join(format!("journal-{}", self.spawned));
        let io = |error: io::Error| error.to_string();
        let listener = UnixListener::bind(&socket).map_err(io)?;
        listener.set_nonblocking(true).map_err(io)?;
        let request: Vec<String> = self.requests[owner].iter().map(usize::to_string).collect();
        let child = ExactChild::spawn(
            CHILD,
            &[
                (ROOT, self.fixture.root.to_str().unwrap()),
                (OWNER, &owner.to_string()),
                (MODE, mode),
                (REQUEST, &request.join(",")),
                (SOCKET, socket.to_str().unwrap()),
                (JOURNAL, journal.to_str().unwrap()),
            ],
        )
        .map_err(io)?;
        let until = Instant::now() + DEADLINE;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => {
                    return Err(format!("binder {owner}'s child did not connect: {error}"));
                }
            }
        };
        stream.set_nonblocking(false).map_err(io)?;
        stream.set_read_timeout(Some(DEADLINE)).map_err(io)?;
        stream.set_write_timeout(Some(DEADLINE)).map_err(io)?;
        self.processes[owner] = Some(Process {
            child,
            stream: BufReader::new(stream),
            stopped: false,
            mode,
            journal,
            guards: BTreeMap::new(),
        });
        Ok(())
    }

    /// Runs `owner`'s next step, which must be `phase` on `device`, and
    /// returns whether it succeeded and, when the call returned with it, the
    /// call's result. A refused step outside [`ROLLED_BACK`] ends the call.
    fn operate(
        &mut self,
        owner: usize,
        phase: &str,
        device: Option<usize>,
        accept: bool,
    ) -> Result<(bool, String), String> {
        let part = self.network_part[owner];
        let process = self.processes[owner]
            .as_mut()
            .ok_or(format!("binder {owner} runs no call"))?;
        process.advance()?;
        let ready = process.report()?;
        if ready.kind != "ready" || ready.phase != phase {
            return Err(format!(
                "binder {owner}'s next step is {ready:?}, not {phase}"
            ));
        }
        if device.is_some_and(|device| ready.device != DEVICES[device]) {
            return Err(format!("{phase} names {}", ready.device));
        }
        if phase.ends_with("etworkBatch") && ready.device != NETWORK_COMMANDS[part] {
            return Err(format!("network command {part} is {}", ready.device));
        }
        process.send("execute", accept)?;
        let done = process.report()?;
        if done.kind != "done" || done.phase != phase {
            return Err(format!("{phase} ended as {done:?}"));
        }
        process.guards = done.guards;
        process.stopped = true;
        let ok = done.result == "ok";
        if ok || ROLLED_BACK.contains(&phase) {
            return Ok((ok, String::new()));
        }
        Ok((false, self.returned(owner)?))
    }

    /// Lets `owner`'s stopped child return from its call, waits for the
    /// child to end and returns the call's result.
    fn returned(&mut self, owner: usize) -> Result<String, String> {
        let mut process = self.processes[owner].take().unwrap();
        process.advance()?;
        let result = process.report()?;
        if result.kind != "result" {
            return Err(format!("binder {owner}'s call went on to {result:?}"));
        }
        let outcome = process.child.finish(Instant::now() + DEADLINE);
        if !exact_child::credited(CHILD, &outcome) {
            return Err(format!("binder {owner}'s child {outcome:?}"));
        }
        Ok(result.result)
    }

    /// Forgets what `owner`'s ended call showed: the devices its bind
    /// moved, the names and writes of its release and its count, modulo
    /// four, of network commands. The model keeps each for the length of
    /// one call.
    fn ended(&mut self, owner: usize) {
        self.moved[owner].clear();
        self.released_names[owner].clear();
        self.release_writes.retain(|(binder, _)| *binder != owner);
        self.network_part[owner] = 0;
    }

    /// Reads `owner`'s journal: the devices its bind wrote a `vfio-pci`
    /// override for, and the devices its release wrote, each of which the
    /// release's record must have named.
    fn read_journal(&mut self, owner: usize) -> Result<(), String> {
        let Some(process) = self.processes[owner].as_ref() else {
            return Ok(());
        };
        let log = fs::read_to_string(&process.journal).unwrap_or_default();
        for write in log.lines().filter_map(|line| line.strip_prefix("write ")) {
            let (write, _record) = write.rsplit_once(' ').ok_or("a journaled write")?;
            let (path, value) = write.split_once('=').ok_or("a journaled write")?;
            let device = DEVICES
                .iter()
                .position(|bdf| path.contains(bdf) || value == *bdf)
                .ok_or(format!("the write {write} names no managed device"))?;
            if process.mode == "release" {
                if !self.released_names[owner].contains(&device) {
                    return Err(format!("the release wrote {write} outside its record"));
                }
                self.release_writes.insert((owner, device));
            } else if path.ends_with("driver_override") && value == VFIO {
                self.moved[owner].insert(device);
            }
        }
        Ok(())
    }

    /// Runs one action of a trace against the children.
    fn execute(&mut self, action: &Action) -> Result<(), String> {
        let (a, device, accept) = (action.binder, action.device, action.accept);
        if a > 1 || device.is_some_and(|device| device > 1) {
            return Err("an action names binders 0 and 1 and devices 0 and 1".into());
        }
        let act = action.act.as_str();
        self.outcome.clear();
        let refused = |result: &str, error: &str| {
            if result.starts_with(error) {
                Ok(())
            } else {
                Err(format!("{act} refused with {result}, not {error}"))
            }
        };
        match act {
            "bindOwner" | "releaseOwner" => {
                if act == "bindOwner" {
                    self.requests[a].clone_from(&action.requested);
                }
                self.start(
                    a,
                    if act == "bindOwner" {
                        "bind"
                    } else {
                        "release"
                    },
                )?;
                if !self.operate(a, "owner", None, true)?.0 {
                    return Err(format!("binder {a} did not take its owner lock"));
                }
            }
            "liveOwnerRefusal" => {
                let live = self.processes[a].take().ok_or("a live owner")?;
                self.start(a, "bind")?;
                let (ok, result) = self.operate(a, "owner", None, true)?;
                self.processes[a] = Some(live);
                if ok {
                    return Err(format!("a second call of binder {a} took its owner lock"));
                }
                refused(&result, "Err(Lock(")?;
                self.outcome = "live-owner-refused".into();
            }
            "crash" => {
                let process = self.processes[a].take().ok_or("a call to kill")?;
                if !process.stopped {
                    return Err(format!("binder {a} is not stopped after a step"));
                }
                let killed = process.child.kill();
                if !matches!(killed, Outcome::Crashed { signal, .. } if signal == libc::SIGKILL) {
                    return Err(format!("binder {a}'s child {killed:?}"));
                }
                self.tally.deaths += 1;
                self.ended(a);
                let published = self.state_dir(a).join("mappings").exists();
                self.outcome = if published {
                    "crash-after-publish"
                } else {
                    "crash-before-publish"
                }
                .into();
            }
            "bindReturn" | "releaseReturn" | "rollbackReturn" => {
                self.operate(a, act, None, true)?;
                let result = self.returned(a)?;
                self.ended(a);
                let (prefix, outcome) = match act {
                    "bindReturn" => ("Ok(", "bound"),
                    "releaseReturn" => ("Ok(", "fresh-release-restores"),
                    _ => ("Err(", "rolled-back"),
                };
                refused(&result, prefix)?;
                self.outcome = outcome.into();
            }
            _ if ACTIONS.contains(&act) => {
                let phase = match act {
                    "bindDeviceLock" | "releaseDeviceLock" => "deviceLock",
                    _ => act,
                };
                let (ok, result) = self.operate(a, phase, device, accept)?;
                self.read_journal(a)?;
                if self.processes[a].is_none() {
                    self.ended(a);
                }
                match (act, ok) {
                    ("publish", true) => self.outcome = "published".into(),
                    ("readRecord", true) => self.released_names[a] = self.raw_names(a)?,
                    ("networkBatch" | "rollbackNetworkBatch", true) => {
                        self.network_part[a] = (self.network_part[a] + 1) % 4;
                    }
                    (_, true) => {}
                    ("secondCapture", false) => self.outcome = "second-capture-refused".into(),
                    ("setOverride" | "unbind" | "vfioBind", false) => {
                        self.outcome = "driver-refused".into();
                    }
                    ("bindPreflight", false) => {
                        refused(&result, "Err(")?;
                        self.outcome = "preflight-refused".into();
                    }
                    ("bindDeviceLock" | "releaseDeviceLock", false) => {
                        refused(&result, "Err(Lock(")?;
                        self.outcome = "contention-refused".into();
                    }
                    ("consultRecords" | "releaseConsult", false) => {
                        refused(&result, "Err(OtherOwner")?;
                        self.outcome = "other-owner-refused".into();
                    }
                    ("groupGuard", false) => {
                        refused(&result, "Err(VfioGroup")?;
                        self.outcome = "guard-refused".into();
                    }
                    ("readRecord", false) => {
                        if !result.contains("NotFound") {
                            return Err(format!("readRecord refused with {result}"));
                        }
                        self.outcome = "fresh-release-refuses-missing".into();
                    }
                    _ => return Err(format!("{act} refused with {result}")),
                }
            }
            _ => return Err(format!("unknown action {act}")),
        }
        self.tally.actions.insert(action.act.clone());
        if !self.outcome.is_empty() {
            self.tally.outcomes.insert(self.outcome.clone());
        }
        Ok(())
    }

    /// The devices the lines of `owner`'s record file name, read without
    /// the record's parser; empty without a file.
    fn raw_names(&self, owner: usize) -> Result<BTreeSet<usize>, String> {
        let raw = match fs::read_to_string(mappings_path(&self.state_dir(owner))) {
            Ok(raw) => raw,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
            Err(error) => return Err(format!("owner {owner}'s record: {error}")),
        };
        let names = |line: String| raw.lines().any(|found| found == line);
        Ok([format!("nvme.bdf={BDF}"), format!("eni.bdf={ENI_BDF}")]
            .into_iter()
            .enumerate()
            .filter_map(|(device, line)| names(line).then_some(device))
            .collect())
    }

    /// The devices `owner`'s record names as [`Mappings::read`] gives it;
    /// empty without a file.
    fn names(&self, owner: usize) -> Result<BTreeSet<usize>, String> {
        let path = mappings_path(&self.state_dir(owner));
        if !path.exists() {
            return Ok(BTreeSet::new());
        }
        let mappings =
            Mappings::read(&path).map_err(|error| format!("owner {owner}'s record: {error:?}"))?;
        let bdfs = mappings
            .nvme
            .iter()
            .map(|nvme| &nvme.bdf)
            .chain(mappings.eni.iter().map(|eni| &eni.eni.bdf));
        bdfs.map(|bdf| {
            DEVICES
                .iter()
                .position(|device| device == bdf)
                .ok_or(format!("owner {owner}'s record names {bdf}"))
        })
        .collect()
    }

    /// Each device on `vfio-pci` is named by exactly one owner's readable
    /// record.
    fn census(&self) -> Result<(), String> {
        let owners = [self.names(0)?, self.names(1)?];
        for (device, bdf) in DEVICES.iter().enumerate() {
            let records = owners
                .iter()
                .filter(|names| names.contains(&device))
                .count();
            if self.fixture.host.driver(bdf).as_deref() == Some(VFIO) && records != 1 {
                return Err(format!(
                    "census: {bdf} is on vfio-pci under {records} records"
                ));
            }
        }
        Ok(())
    }

    /// The child holding the lock file at `path`, by the lock lines of each
    /// child's `/proc/<pid>/fdinfo`, or -1 for a lock a nonblocking probe
    /// takes. A lock the probe cannot take fails: a process outside both
    /// children holds it, or the file's device number differs from the one
    /// the kernel's lock lines print.
    fn lock_holder(&self, path: &Path) -> Result<i64, String> {
        let Ok(meta) = fs::metadata(path) else {
            return Ok(-1);
        };
        let (major, minor) = (libc::major(meta.dev()), libc::minor(meta.dev()));
        let key = format!("{major:02x}:{minor:02x}:{}", meta.ino());
        let mut holders = Vec::new();
        for (owner, process) in self.processes.iter().enumerate() {
            let Some(process) = process else { continue };
            let io = |error: io::Error| error.to_string();
            for fd in fs::read_dir(format!("/proc/{}/fdinfo", process.child.id())).map_err(io)? {
                let info = fs::read_to_string(fd.map_err(io)?.path()).unwrap_or_default();
                let locked = info
                    .lines()
                    .filter_map(|line| line.strip_prefix("lock:"))
                    .any(|lock| lock.split_whitespace().nth(5) == Some(key.as_str()));
                if locked {
                    holders.push(owner as i64);
                }
            }
        }
        match holders[..] {
            [holder] => Ok(holder),
            [] => {
                // The probe's descriptor holds the lock while open, so no
                // test spawns a child meanwhile.
                let live = Live::enter();
                let probe = File::open(path).map(|file| file.try_lock());
                drop(live);
                match probe {
                    Ok(Ok(())) => Ok(-1),
                    other => Err(format!(
                        "{path:?} is locked and no child's fdinfo names {key}: {other:?}"
                    )),
                }
            }
            _ => Err(format!("{path:?} has holders {holders:?}")),
        }
    }

    /// The child holding an open group guard of `bdf`, or -1.
    fn guard_holder(&self, bdf: &str) -> Result<i64, String> {
        for (owner, process) in self.processes.iter().enumerate() {
            let Some(process) = process else { continue };
            let Some((fd, inode, rdev)) = process.guards.get(bdf) else {
                continue;
            };
            let open = fs::metadata(format!("/proc/{}/fd/{fd}", process.child.id()));
            if !open.is_ok_and(|meta| meta.ino() == *inode && meta.rdev() == *rdev) {
                return Err(format!("binder {owner} closed its guard of {bdf}"));
            }
            return Ok(owner as i64);
        }
        Ok(-1)
    }

    /// The ENI's network state as the model codes it: one bit each for its
    /// MTU, link state, addresses, routes and resolved next hops.
    fn network(&self) -> Result<i64, String> {
        let net = self.fixture.host.sys.join("class/net").join(ENI_NETDEV);
        let neighbors = self.fixture.root.join("neigh").join(ENI_NETDEV);
        let hops = "10.0.1.9 lladdr 0a:00:00:00:01:09 REACHABLE\n\
                    10.0.1.1 lladdr 0a:00:00:00:01:01 REACHABLE\n";
        let mut code = 0;
        for (bit, path, reset, restored) in [
            (1, net.join("mtu"), "1500\n", "9001\n"),
            (2, net.join("flags"), "0x1002\n", "0x1003\n"),
            (4, net.join("addresses"), "", ADDRESSES),
            (8, net.join("routes"), "", ROUTES),
            (16, neighbors, "", hops),
        ] {
            let found = fs::read_to_string(&path).map_err(|error| format!("{path:?}: {error}"))?;
            match found.as_str() {
                found if found == restored => code += bit,
                found if found == reset => {}
                found => return Err(format!("{path:?} holds {found:?}")),
            }
        }
        Ok(code)
    }

    /// What the children and the fixture tree show, under the names of the
    /// model's state.
    fn observed(&self) -> Result<Value, String> {
        self.census()?;
        let sets = |sets: &[BTreeSet<usize>; 2]| json!([sets[0], sets[1]]);
        let mut present = Vec::new();
        let mut raw_records = Vec::new();
        for owner in 0..2 {
            let raw = self.raw_names(owner)?;
            present.push(mappings_path(&self.state_dir(owner)).exists());
            raw_records.push(i64::from(raw.contains(&0)) + 2 * i64::from(raw.contains(&1)));
        }
        let mut owners = Vec::new();
        for owner in 0..2 {
            let holder = self.lock_holder(&self.state_dir(owner).join("bind.lock"))?;
            if holder != -1 && holder != owner as i64 {
                return Err(format!("binder {holder} holds owner {owner}'s lock"));
            }
            owners.push(holder != -1);
        }
        let (mut locks, mut guards, mut driver, mut overrides) = (vec![], vec![], vec![], vec![]);
        for (device, bdf) in DEVICES.iter().enumerate() {
            let lock = self.fixture.device_locks().join(format!("{bdf}.lock"));
            locks.push(self.lock_holder(&lock)?);
            guards.push(self.guard_holder(bdf)?);
            let kernel = KERNEL_DRIVERS[device];
            driver.push(match self.fixture.host.driver(bdf).as_deref() {
                Some(name) if name == kernel => 0,
                None => 1,
                Some(VFIO) => 2,
                other => return Err(format!("{bdf} is on {other:?}")),
            });
            overrides.push(
                match self.fixture.host.driver_override(bdf).flatten().as_deref() {
                    None => 0,
                    Some(VFIO) => 2,
                    Some(name) if name == kernel => 3,
                    other => return Err(format!("{bdf} has the override {other:?}")),
                },
            );
        }
        Ok(json!({
            "owner": owners,
            "locks": locks,
            "guards": guards,
            "present": present,
            "records": sets(&[self.names(0)?, self.names(1)?]),
            "rawRecords": raw_records,
            "driver": driver,
            "overrides": overrides,
            "network": self.network()?,
            "networkPart": self.network_part,
            "moved": sets(&self.moved),
            "releasedNames": sets(&self.released_names),
            "releaseWrites": self.release_writes,
            "outcome": self.outcome,
        }))
    }
}

/// Rewrites ITF's `#bigint`, `#set` and `#tup` values as numbers and arrays,
/// a set's members in ascending order.
fn plain(value: &mut Value) {
    match value {
        Value::Object(map) if map.contains_key("#bigint") => {
            *value = map["#bigint"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap()
                .into();
        }
        Value::Object(map) if map.contains_key("#set") || map.contains_key("#tup") => {
            let ordered = map.contains_key("#tup");
            let mut members = map.values_mut().next().unwrap().take();
            plain(&mut members);
            if !ordered {
                let members = members.as_array_mut().unwrap();
                members.sort_by_key(|member| member.to_string());
            }
            *value = members;
        }
        Value::Object(map) => map.values_mut().for_each(plain),
        Value::Array(list) => list.iter_mut().for_each(plain),
        _ => {}
    }
}

impl Replay {
    /// Replays `trace` and returns the count of its actions. The trace must
    /// record this model's digest, one state per action of its recipe after
    /// the initial state, and in each state the recipe's action. The error
    /// names the first action whose step or state differs.
    fn run(&mut self, trace: &str) -> Result<usize, String> {
        let mut trace: Value = serde_json::from_str(trace).map_err(|error| error.to_string())?;
        plain(&mut trace);
        let meta = &trace["#meta"]["binder"];
        let digest: String = Sha256::digest(MODEL)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if meta["model_sha256"] != digest {
            return Err("fixture model digest".into());
        }
        let recipe = meta["recipe"].as_array().ok_or("fixture recipe")?;
        let states = trace["states"].as_array().ok_or("fixture states")?;
        if states.len() != recipe.len() + 1 {
            return Err("fixture recipe length".into());
        }
        for (at, state) in states.iter().enumerate() {
            if at > 0 {
                let action = Action::of(&state["binderCase::binder::last"])
                    .map_err(|field| format!("action {at}: {field}"))?;
                if state["mbt::actionTaken"] != action.act.as_str()
                    || recipe[at - 1] != action.recipe().as_str()
                {
                    return Err(format!("action {at}: recipe"));
                }
                self.execute(&action)
                    .map_err(|error| format!("action {at} {}: {error}", action.act))?;
            }
            let observed = self
                .observed()
                .map_err(|error| format!("action {at}: {error}"))?;
            let model = &state["binderCase::binder::st"];
            for (field, seen) in observed.as_object().unwrap() {
                if model[field] != *seen {
                    return Err(format!(
                        "action {at}: {field} is {seen}, the model has {}",
                        model[field]
                    ));
                }
            }
        }
        Ok(recipe.len())
    }
}

/// Replays each fixture of `traces`, requires the campaign's coverage and
/// prints the count the `quint` lane's judge reads.
fn replay_all(traces: [(&str, &str); 2]) {
    let mut actions = 0;
    for (name, trace) in traces {
        let mut replay = Replay::new();
        actions += replay
            .run(trace)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let tally = &replay.tally;
        if name == "campaign" {
            assert_eq!(tally.actions, ACTIONS.map(String::from).into());
            assert_eq!(tally.outcomes, CAMPAIGN_OUTCOMES.map(String::from).into());
            assert_eq!(tally.deaths, CAMPAIGN_DEATHS);
        }
    }
    println!("core replay: traces=2 actions={actions} agreement=all");
}

/// Both binders' real processes take every step of the committed traces in
/// the traces' order and leave the state the model gives after each.
#[test]
fn committed_traces_replay() {
    replay_all(FIXTURES);
}

/// Quint regenerates each trace; the committed fixture must equal it, so
/// the replay of the committed fixtures replays the model's traces.
#[test]
#[ignore = "generated binder traces; the quint lane runs it with Quint on PATH"]
fn generated_traces_replay() {
    let out = std::env::temp_dir().join(format!("binder-replay-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = std::process::Command::new("python3")
        .arg(root.join("quint/binder_check.py"))
        .args(["--quint", "quint"])
        .arg("--output")
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "trace generation completed");
    let generated = FIXTURES.map(|(name, committed)| {
        let generated = fs::read_to_string(out.join(format!("{name}.itf.json"))).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&generated).unwrap(),
            serde_json::from_str::<Value>(committed).unwrap(),
            "{name}: the committed trace differs from the model's"
        );
        (name, generated)
    });
    let _ = fs::remove_dir_all(&out);
    replay_all(
        generated
            .each_ref()
            .map(|(name, trace)| (*name, trace.as_str())),
    );
}

/// The lock-gap prefix with `edit` applied to its parsed trace.
fn edited(edit: impl FnOnce(&mut Value)) -> String {
    let mut trace: Value = serde_json::from_str(LOCK_GAP_PREFIX).unwrap();
    edit(&mut trace);
    trace.to_string()
}

const STATE: &str = "binderCase::binder::st";
const LAST: &str = "binderCase::binder::last";

/// A model state that differs from the processes and the tree in one field
/// fails at its action and names the field: a device lock's holder, a
/// driver, an owner lock and the action's outcome.
#[test]
fn an_altered_model_state_fails_at_its_action() {
    let minus_one = json!({"#bigint": "-1"});
    type Edit<'e> = (usize, Box<dyn Fn(&mut Value) + 'e>, &'e str);
    let cases: [Edit<'_>; 4] = [
        (
            3,
            Box::new(|st| st["locks"][0] = minus_one.clone()),
            "action 3: locks is [0,-1], the model has [-1,-1]",
        ),
        (
            0,
            Box::new(|st| st["driver"][1] = json!({"#bigint": "2"})),
            "action 0: driver is [0,0], the model has [0,2]",
        ),
        (
            5,
            Box::new(|st| st["owner"][1] = json!(false)),
            "action 5: owner is [true,true], the model has [true,false]",
        ),
        (
            7,
            Box::new(|st| st["outcome"] = json!("")),
            "action 7: outcome is \"contention-refused\", the model has \"\"",
        ),
    ];
    for (at, edit, error) in cases {
        let trace = edited(|trace| edit(&mut trace["states"][at][STATE]));
        assert_eq!(Replay::new().run(&trace).unwrap_err(), error);
    }
}

/// A trace of another model text, a trace cut short of its recipe, and a
/// state whose action differs from its recipe entry are refused.
#[test]
fn a_stale_model_a_cut_trace_and_an_action_off_its_recipe_are_refused() {
    type Edit = (fn(&mut Value), &'static str);
    let cases: [Edit; 4] = [
        (
            |trace| trace["#meta"]["binder"]["model_sha256"] = json!("0"),
            "fixture model digest",
        ),
        (
            |trace| drop(trace["states"].as_array_mut().unwrap().pop()),
            "fixture recipe length",
        ),
        (
            |trace| trace["#meta"]["binder"]["recipe"][2] = json!("bindDeviceLock(0, 1)"),
            "action 3: recipe",
        ),
        (
            |trace| trace["states"][2]["mbt::actionTaken"] = json!("publish"),
            "action 2: recipe",
        ),
    ];
    for (edit, error) in cases {
        assert_eq!(Replay::new().run(&edited(edit)).unwrap_err(), error);
    }
}

/// A trace that asks for the consultation where the binder's next step is
/// its device lock fails at that action: the children's step order stands
/// for the model's step counter.
#[test]
fn a_trace_that_skips_a_step_of_the_binder_fails_at_that_action() {
    let trace = edited(|trace| {
        trace["#meta"]["binder"]["recipe"][2] = json!("consultRecords(0)");
        let state = &mut trace["states"][3];
        state["mbt::actionTaken"] = json!("consultRecords");
        state[LAST]["act"] = json!("consultRecords");
        state[LAST]["device"] = json!({"#bigint": "-1"});
    });
    let error = Replay::new().run(&trace).unwrap_err();
    assert!(
        error.starts_with("action 3 consultRecords: binder 0's next step is ")
            && error.contains("deviceLock"),
        "{error}"
    );
}

/// A second owner's record of a device on `vfio-pci` fails the census of
/// the next observation. Binder 0 is killed after its record; a bind for
/// owner 1 that consults no other directory then records and moves the same
/// devices.
#[test]
fn two_readable_records_of_a_device_on_vfio_fail_the_census() {
    let mut trace: Value = serde_json::from_str(CAMPAIGN).unwrap();
    let states = trace["states"].as_array().unwrap();
    let killed = states
        .iter()
        .position(|state| state[STATE]["outcome"] == "crash-after-publish")
        .unwrap();
    trace["states"].as_array_mut().unwrap().truncate(killed + 1);
    let recipe = &mut trace["#meta"]["binder"]["recipe"];
    recipe.as_array_mut().unwrap().truncate(killed);
    let mut replay = Replay::new();
    assert_eq!(replay.run(&trace.to_string()), Ok(killed));
    // The bind's locks are closed again before any child is spawned.
    let live = Live::enter();
    let host = replay.fixture.host.clone();
    let binder = Binder {
        kernel: FakeKernel::new(&host),
        state_dir: replay.state_dir(1),
        host,
    };
    let manifest = Fixture::manifest_of(&binder.host);
    let metadata = FakeMetadata::new();
    binder
        .bind(&BindRequest {
            volume: Some(VOLUME),
            eni: Some(EniRequest {
                id: ENI,
                peers: &PEERS,
                metadata: &metadata,
            }),
            posture: ALLOWLISTED,
            wc: &manifest,
            others: &[],
        })
        .unwrap();
    drop(live);
    assert_eq!(
        replay.observed().unwrap_err(),
        format!("census: {BDF} is on vfio-pci under 2 records")
    );
}
