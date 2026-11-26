//! Binder processes killed at every modeled transition of bind and release,
//! each witnessed by a surviving parent.
//!
//! The parent owns the fixture tree: the fake sysfs, the state directory and
//! the device lock directory live under its root, so they survive a child's
//! death. A child runs [`the_binder_child_runs_its_action_to_its_cut`] by
//! exact test ID in a fresh process, with the root, the action, the cut and
//! its journal path in its environment. At the cut it reports the cut and
//! blocks. The parent sends `SIGKILL`, waits for the child, and only then
//! reads the record's raw bytes, the fixture's driver links and overrides,
//! and the child's journal, which logs every driver write with the record
//! bytes at that moment, and every command. A fresh child then releases
//! with no cut, and its journal and result are judged the same way.
//!
//! Every cut maps to one disposition. A cut before the record's rename
//! leaves no record and every driver unchanged. A cut once the record's
//! rename lands and before a release or a rollback unlinks it leaves a
//! valid record naming the pre-bind state, from which a fresh release
//! restores every device and removes the record. A cut after a release or
//! a rollback unlinks the record leaves every device restored and no
//! record, and a fresh release refuses on the missing record with no
//! write.
//!
//! The kill models process death on a running system: the page cache
//! survives, and power loss is outside what these cases show. Recovery
//! assumes the same host and boot, the approved modules, free locks and the
//! fixture's successful calls. The frozen matrix [`CUTS`] runs within each
//! case's declared deadline; a cut the child never reports is missing
//! evidence and fails.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::binder::{BindError, Binder, VFIO, mappings_path};
use super::binder_tests::bind_eni;
use super::fixture::{
    BDF, BOOT, ENI_BDF, FakeKernel, FakeMetadata, Fixture, INSTANCE, Journal, VOLUME, host_at,
    neighbor_entry,
};
use super::host::Kernel;
use super::mappings::{Mappings, MappingsError};
use super::record_step::{RecordStep, SCRIPT, Script};
use crate::exact_child::{self, ExactChild, Outcome};

/// The child test's own ID, which the parent runs by exact name.
const CHILD: &str = "bind::cut_tests::the_binder_child_runs_its_action_to_its_cut";

/// The environment the parent hands each child.
const ROOT: &str = "KESTRIKE_BIND_CUT_ROOT";
const ACTION: &str = "KESTRIKE_BIND_CUT_ACTION";
const AT: &str = "KESTRIKE_BIND_CUT_AT";
const JOURNAL: &str = "KESTRIKE_BIND_CUT_JOURNAL";
/// The milliseconds a child blocked at its cut waits before it exits.
const STRAY: &str = "KESTRIKE_BIND_CUT_STRAY_MS";

/// Each episode's deadline: one child's run to its cut or its end. A child
/// starts, binds or releases and reaches its cut in under one second in an
/// unoptimized build on a development host; thirty seconds leaves room for
/// a loaded workspace runner.
const DEADLINE: Duration = Duration::from_secs(30);

/// A child blocked at its cut exits after this duration, twenty times
/// [`DEADLINE`], which bounds a child that outlives its parent.
const LIFETIME: Duration = Duration::from_secs(600);

/// The exit code [`rendezvous`] uses to end a child once the [`STRAY`]
/// milliseconds pass.
const STRAYED: i32 = 4;

/// The devices the fixture holds beside the two the binder moves: the boot
/// volume's controller and the primary interface, which no step may touch.
const UNRELATED: [&str; 2] = ["0000:00:04.0", "0000:00:05.0"];

/// Where a cut stops a child.
#[derive(Clone, Copy, Debug)]
enum Site {
    /// Before the `n`th occurrence of a record step, counting from one.
    Record(RecordStep, usize),
    /// Before the write the pattern names takes effect.
    BeforeWrite(&'static str),
    /// After the write the pattern names takes effect, before the binder
    /// sees its reply.
    AfterWrite(&'static str),
    /// While the command line runs, before its answer.
    DuringRun(&'static str),
    /// After the action returns, before the child reports its result.
    Returned,
}

/// The state a cut leaves, which the parent checks after the child's death.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    /// No record was published, and every driver is unchanged.
    Unpublished,
    /// A valid record names the pre-bind state, and a fresh release
    /// restores from it and removes it.
    Recorded,
    /// Every device is restored and the record removed, and a fresh release
    /// refuses on the missing record with no write.
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Bind,
    Release,
    /// A broken release for the convergence control: it removes the record
    /// and restores nothing.
    DiscardingRelease,
}

impl Action {
    const ALL: [Self; 3] = [Self::Bind, Self::Release, Self::DiscardingRelease];

    /// The action's name in a child's environment.
    fn name(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Release => "release",
            Self::DiscardingRelease => "discarding-release",
        }
    }
}

/// One frozen cut: its stable name, the action the killed child runs, the
/// driver write its kernel refuses, where it stops, the disposition the
/// parent checks and the deadline it declares.
struct Cut {
    name: &'static str,
    action: Action,
    fail: Option<&'static str>,
    site: Site,
    disposition: Disposition,
    deadline: Duration,
}

const fn cut(name: &'static str, action: Action, site: Site, disposition: Disposition) -> Cut {
    Cut {
        name,
        action,
        fail: None,
        site,
        disposition,
        deadline: DEADLINE,
    }
}

/// A cut in the rollback of a bind whose ENI unbind the kernel refuses,
/// after the controller moved.
const fn rollback(name: &'static str, site: Site, disposition: Disposition) -> Cut {
    Cut {
        fail: Some("ena/unbind=0000:00:06.0"),
        ..cut(name, Action::Bind, site, disposition)
    }
}

/// The cut `name` names in the frozen matrix.
fn cut_named(name: &str) -> &'static Cut {
    CUTS.iter()
        .find(|cut| cut.name == name)
        .unwrap_or_else(|| panic!("{name} is a declared cut"))
}

/// The frozen cut matrix of the combined controller and ENI bind, its
/// rollback, and its release.
const CUTS: [Cut; 34] = [
    cut(
        "bind/next-hop-flush",
        Action::Bind,
        Site::DuringRun("ip -4 neigh flush to 10.0.1.1 dev ens6"),
        Disposition::Unpublished,
    ),
    cut(
        "bind/record-create",
        Action::Bind,
        Site::Record(RecordStep::Create, 1),
        Disposition::Unpublished,
    ),
    cut(
        "bind/record-rename",
        Action::Bind,
        Site::Record(RecordStep::Rename, 1),
        Disposition::Unpublished,
    ),
    cut(
        "bind/record-renamed",
        Action::Bind,
        Site::Record(RecordStep::DirectoryOpen, 1),
        Disposition::Recorded,
    ),
    cut(
        "bind/first-driver-write",
        Action::Bind,
        Site::BeforeWrite("1f.0/driver_override"),
        Disposition::Recorded,
    ),
    cut(
        "bind/controller-override",
        Action::Bind,
        Site::AfterWrite("1f.0/driver_override"),
        Disposition::Recorded,
    ),
    cut(
        "bind/controller-unbind",
        Action::Bind,
        Site::AfterWrite("nvme/unbind=0000:00:1f.0"),
        Disposition::Recorded,
    ),
    cut(
        "bind/controller-bind",
        Action::Bind,
        Site::AfterWrite("vfio-pci/bind=0000:00:1f.0"),
        Disposition::Recorded,
    ),
    cut(
        "bind/eni-override",
        Action::Bind,
        Site::AfterWrite("06.0/driver_override"),
        Disposition::Recorded,
    ),
    cut(
        "bind/eni-unbind",
        Action::Bind,
        Site::AfterWrite("ena/unbind=0000:00:06.0"),
        Disposition::Recorded,
    ),
    cut(
        "bind/eni-bind",
        Action::Bind,
        Site::AfterWrite("vfio-pci/bind=0000:00:06.0"),
        Disposition::Recorded,
    ),
    cut(
        "bind/returned",
        Action::Bind,
        Site::Returned,
        Disposition::Recorded,
    ),
    rollback(
        "rollback/controller-unbind",
        Site::BeforeWrite("1f.0/driver_override=nvme"),
        Disposition::Recorded,
    ),
    rollback(
        "rollback/controller-override",
        Site::AfterWrite("1f.0/driver_override=nvme"),
        Disposition::Recorded,
    ),
    rollback(
        "rollback/controller-bind",
        Site::AfterWrite("nvme/bind"),
        Disposition::Recorded,
    ),
    rollback(
        "rollback/controller-override-cleared",
        Site::AfterWrite("1f.0/driver_override=\n"),
        Disposition::Recorded,
    ),
    rollback(
        "rollback/eni-override-cleared",
        Site::AfterWrite("06.0/driver_override=\n"),
        Disposition::Recorded,
    ),
    rollback(
        "rollback/network-batch",
        Site::DuringRun("ip link set dev if6 up"),
        Disposition::Recorded,
    ),
    rollback(
        "rollback/unlink",
        Site::Record(RecordStep::Unlink, 1),
        Disposition::Recorded,
    ),
    rollback(
        "rollback/unlinked",
        Site::Record(RecordStep::DirectoryOpen, 2),
        Disposition::Released,
    ),
    cut(
        "release/first-restore-write",
        Action::Release,
        Site::BeforeWrite("vfio-pci/unbind=0000:00:1f.0"),
        Disposition::Recorded,
    ),
    cut(
        "release/controller-unbind",
        Action::Release,
        Site::AfterWrite("vfio-pci/unbind=0000:00:1f.0"),
        Disposition::Recorded,
    ),
    cut(
        "release/controller-override",
        Action::Release,
        Site::AfterWrite("1f.0/driver_override=nvme"),
        Disposition::Recorded,
    ),
    cut(
        "release/controller-bind",
        Action::Release,
        Site::AfterWrite("nvme/bind"),
        Disposition::Recorded,
    ),
    cut(
        "release/eni-unbind",
        Action::Release,
        Site::AfterWrite("vfio-pci/unbind=0000:00:06.0"),
        Disposition::Recorded,
    ),
    cut(
        "release/eni-override",
        Action::Release,
        Site::AfterWrite("06.0/driver_override=ena"),
        Disposition::Recorded,
    ),
    cut(
        "release/controller-override-cleared",
        Action::Release,
        Site::AfterWrite("1f.0/driver_override=\n"),
        Disposition::Recorded,
    ),
    cut(
        "release/controller-restored",
        Action::Release,
        Site::BeforeWrite("vfio-pci/unbind=0000:00:06.0"),
        Disposition::Recorded,
    ),
    cut(
        "release/eni-override-cleared",
        Action::Release,
        Site::AfterWrite("06.0/driver_override=\n"),
        Disposition::Recorded,
    ),
    cut(
        "release/eni-bind",
        Action::Release,
        Site::AfterWrite("ena/bind"),
        Disposition::Recorded,
    ),
    cut(
        "release/network-batch",
        Action::Release,
        Site::DuringRun("ip link set dev if6 up"),
        Disposition::Recorded,
    ),
    cut(
        "release/unlink",
        Action::Release,
        Site::Record(RecordStep::Unlink, 1),
        Disposition::Recorded,
    ),
    cut(
        "release/unlinked",
        Action::Release,
        Site::Record(RecordStep::DirectoryOpen, 1),
        Disposition::Released,
    ),
    cut(
        "release/returned",
        Action::Release,
        Site::Returned,
        Disposition::Released,
    ),
];

/// The report a child writes once it stops at its cut.
fn reached(name: &str) -> String {
    format!("cut {name}")
}

/// The [`STRAY`] bound ends a child whose parent died without killing it.
fn rendezvous(name: &'static str) -> ! {
    exact_child::report(&reached(name));
    let lifetime = std::env::var(STRAY)
        .ok()
        .and_then(|millis| millis.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| panic!("{STRAY} names milliseconds"));
    let start = Instant::now();
    while let Some(left) = lifetime.checked_sub(start.elapsed()) {
        std::thread::park_timeout(left);
    }
    std::process::exit(STRAYED);
}

/// The child's side: when the marker names this test, it runs the action
/// its environment names over the parent's fixture tree, stopping at the
/// named cut, and reports its result when no cut stops it. Outside a child
/// it does nothing.
#[test]
fn the_binder_child_runs_its_action_to_its_cut() {
    if !exact_child::is_child(CHILD) {
        return;
    }
    exact_child::report(&exact_child::entered(CHILD));
    let env = |key: &str| std::env::var(key).unwrap_or_else(|_| panic!("{key} is set"));
    let root = PathBuf::from(env(ROOT));
    let named = env(ACTION);
    let action = Action::ALL
        .into_iter()
        .find(|action| action.name() == named)
        .unwrap_or_else(|| panic!("unknown action {named}"));
    let cut = Some(env(AT))
        .filter(|name| !name.is_empty())
        .map(|name| cut_named(&name));
    let binder = journaled_binder(&root, Path::new(&env(JOURNAL)), cut);
    let result = match action {
        Action::Bind => bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).map(drop),
        Action::Release => binder.release(&[]),
        Action::DiscardingRelease => Mappings::discard(&mappings_path(&binder.state_dir))
            .map_err(|error| BindError::Mappings(MappingsError::Io(error))),
    };
    if let Some(cut) = cut.filter(|cut| matches!(cut.site, Site::Returned)) {
        rendezvous(cut.name);
    }
    exact_child::report(&format!("result {result:?}"));
}

/// The kernel and the record steps append to one `journal`, in the order
/// the binder reaches them. Record steps are observed through the
/// thread-local [`SCRIPT`], so they use the journal from the calling
/// thread's most recent `journaled_binder` call.
///
/// With `cut`, the binder blocks in [`rendezvous`] at the cut's record,
/// write or command site; a [`Site::Returned`] cut is the caller's to block
/// at.
fn journaled_binder(root: &Path, journal: &Path, cut: Option<&'static Cut>) -> Binder<FakeKernel> {
    let host = host_at(root);
    let state_dir = root.join("run");
    let kernel = FakeKernel::new(&host);
    let open = || {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal)
            .unwrap()
    };
    kernel.journal.replace(Some(Journal {
        log: open(),
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
    kernel.fail.replace(cut.and_then(|cut| cut.fail));
    observe_steps(open(), cut);
    if let Some(cut) = cut {
        arm(&kernel, cut);
    }
    Binder {
        host,
        kernel,
        state_dir,
    }
}

/// Appends each record step the calling thread reaches to `log`, as `step
/// <RecordStep>`, before the step's call, and blocks at the step occurrence
/// `cut` names.
fn observe_steps(mut log: File, cut: Option<&'static Cut>) {
    let mut seen = 0;
    SCRIPT.with(|script| {
        *script.borrow_mut() = Some(Script {
            outcomes: Vec::new(),
            reached: Vec::new(),
            observe: Box::new(move |at| {
                log.write_all(format!("step {at:?}\n").as_bytes()).unwrap();
                if let Some(
                    cut @ Cut {
                        site: Site::Record(step, occurrence),
                        ..
                    },
                ) = cut
                    && at == *step
                {
                    seen += 1;
                    if seen == *occurrence {
                        rendezvous(cut.name);
                    }
                }
            }),
        })
    });
}

/// Arms `cut`'s fake kernel hook in this child, which blocks at its site.
fn arm(kernel: &FakeKernel, cut: &'static Cut) {
    let name = cut.name;
    match cut.site {
        Site::BeforeWrite(pattern) => {
            kernel.before_write.replace(Some((
                pattern,
                Box::new(move || {
                    rendezvous(name);
                }),
            )));
        }
        Site::AfterWrite(pattern) => {
            kernel.after_write.replace(Some((
                pattern,
                Box::new(move || {
                    rendezvous(name);
                }),
            )));
        }
        Site::DuringRun(line) => {
            kernel.during_run.replace(Some((
                line.to_owned(),
                Box::new(move || {
                    rendezvous(name);
                }),
            )));
        }
        Site::Record(..) | Site::Returned => {}
    }
}

/// One journal entry a child wrote.
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    /// A driver write: its control file relative to sysfs, its value, and
    /// the record's bytes when it was issued, `None` when absent.
    Write {
        path: String,
        value: String,
        record: Option<Vec<u8>>,
    },
    Run(String),
    /// A record step, logged before its call.
    Step(String),
}

fn journal(path: &Path) -> Vec<Entry> {
    let text = fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .map(|line| {
            if let Some(command) = line.strip_prefix("run ") {
                return Entry::Run(command.to_owned());
            }
            if let Some(step) = line.strip_prefix("step ") {
                return Entry::Step(step.to_owned());
            }
            let fields = line.strip_prefix("write ").expect("a journal entry");
            let (write, record) = fields.rsplit_once(' ').unwrap();
            let (path, value) = write.split_once('=').unwrap();
            let record = (record != "-").then(|| {
                (0..record.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&record[at..at + 2], 16).unwrap())
                    .collect()
            });
            Entry::Write {
                path: path.to_owned(),
                value: value.to_owned(),
                record,
            }
        })
        .collect()
}

/// A device's driver and override, as the fixture's sysfs shows them.
type DriverState = (Option<String>, Option<String>);

/// The parent's fixture: the tree every child acts on, and the drivers and
/// network state it held before any bind.
struct Episode {
    fixture: Fixture,
    snapshot: Vec<(&'static str, DriverState)>,
    mtu: String,
    children: usize,
    /// The lifetime each spawned child has once it blocks at its cut.
    lifetime: Duration,
}

impl Episode {
    fn new() -> Self {
        let fixture = Fixture::new(4096).unlisted();
        // Both next hops start stale, so the bind's neighbor batch flushes
        // two entries and a cut can fall between them.
        fixture.file(
            "neigh/ens6",
            &(neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "STALE")
                + &neighbor_entry("10.0.1.1", Some("0a:00:00:00:01:01"), "STALE")),
        );
        let snapshot = [BDF, ENI_BDF]
            .into_iter()
            .chain(UNRELATED)
            .map(|bdf| (bdf, Self::state_of(&fixture, bdf)))
            .collect();
        let mtu = fs::read_to_string(fixture.host.sys.join("class/net/ens6/mtu")).unwrap();
        let on = |driver: &str| (Some(driver.to_owned()), None);
        assert_eq!(
            snapshot,
            [
                (BDF, on("nvme")),
                (ENI_BDF, on("ena")),
                (UNRELATED[0], on("nvme")),
                (UNRELATED[1], on("ena")),
            ],
            "the fixture's pre-bind drivers"
        );
        Self {
            fixture,
            snapshot,
            mtu,
            children: 0,
            lifetime: LIFETIME,
        }
    }

    fn state_of(fixture: &Fixture, bdf: &str) -> DriverState {
        (
            fixture.host.driver(bdf),
            fixture.host.driver_override(bdf).flatten(),
        )
    }

    fn record(&self) -> PathBuf {
        mappings_path(&self.fixture.state_dir())
    }

    /// Spawns a child running `action` to `cut`, or to its end when `cut` is
    /// `None`, and returns it with its journal's path.
    fn spawn(&mut self, action: Action, cut: Option<&Cut>) -> (ExactChild, PathBuf) {
        self.children += 1;
        let journal = self.fixture.root.join(format!("journal-{}", self.children));
        let root = self.fixture.root.to_str().unwrap().to_owned();
        let lifetime = self.lifetime.as_millis().to_string();
        let env = [
            (ROOT, root.as_str()),
            (ACTION, action.name()),
            (AT, cut.map_or("", |cut| cut.name)),
            (JOURNAL, journal.to_str().unwrap()),
            (STRAY, lifetime.as_str()),
        ];
        (ExactChild::spawn(CHILD, &env).unwrap(), journal)
    }

    /// Runs `action` in a child to its end and returns its reported result
    /// and its journal.
    fn complete(&mut self, action: Action, deadline: Duration) -> (String, Vec<Entry>) {
        let (child, path) = self.spawn(action, None);
        let outcome = child.finish(Instant::now() + deadline);
        let Outcome::Completed { reports } = &outcome else {
            panic!("{action:?} in a fresh process: {outcome:?}");
        };
        assert!(reports.contains(&exact_child::entered(CHILD)));
        let result = reports
            .iter()
            .find_map(|report| report.strip_prefix("result "))
            .unwrap_or_else(|| panic!("{action:?} reports its result: {reports:?}"))
            .to_owned();
        (result, journal(&path))
    }

    /// Runs `action` in a child to `cut`, kills it there and waits for it,
    /// and returns its journal once its death is confirmed.
    fn kill_at(&mut self, cut: &Cut) -> Vec<Entry> {
        let (mut child, path) = self.spawn(cut.action, Some(cut));
        let until = Instant::now() + cut.deadline;
        let mut reports = Vec::new();
        while let Some(report) = child.next_report(until) {
            let at = report == reached(cut.name);
            reports.push(report);
            if at {
                let outcome = child.kill();
                assert!(
                    matches!(
                        outcome,
                        Outcome::Crashed {
                            signal: libc::SIGKILL,
                            ..
                        }
                    ),
                    "{} dies by the kill: {outcome:?}",
                    cut.name
                );
                return journal(&path);
            }
        }
        let outcome = child.finish(until);
        panic!(
            "{} was not reached within {:?}, missing evidence: {reports:?}\n{outcome:?}",
            cut.name, cut.deadline
        );
    }

    fn drivers(&self) -> Vec<(&'static str, DriverState)> {
        self.snapshot
            .iter()
            .map(|(bdf, _)| (*bdf, Self::state_of(&self.fixture, bdf)))
            .collect()
    }

    /// Checks that every recorded original value in `bytes` is the pre-bind
    /// snapshot's, and the host and boot are the fixture's, and returns the
    /// addresses the record names.
    fn names_the_snapshot(&self, bytes: &[u8]) -> [String; 2] {
        let copy = self.fixture.root.join("record-copy");
        fs::write(&copy, bytes).unwrap();
        let record = Mappings::read(&copy).expect("a complete, valid record");
        fs::remove_file(copy).unwrap();
        assert_eq!(
            (record.instance.as_str(), record.boot.as_str()),
            (INSTANCE, BOOT)
        );
        let original = |bdf: &str| {
            self.snapshot
                .iter()
                .find(|(at, _)| *at == bdf)
                .map(|(_, state)| state.clone())
                .unwrap()
        };
        let nvme = record.nvme.expect("the controller is recorded");
        assert_eq!(nvme.bdf, BDF);
        assert_eq!(
            (Some(nvme.original_driver), nvme.original_override),
            original(BDF)
        );
        let eni = record.eni.expect("the ENI is recorded");
        assert_eq!(eni.eni.bdf, ENI_BDF);
        let named = [nvme.bdf.clone(), eni.eni.bdf.clone()];
        assert_eq!(
            (Some(eni.original_driver), eni.original_override),
            original(ENI_BDF)
        );
        assert_eq!(eni.net.mtu.to_string(), self.mtu.trim());
        assert!(eni.net.up);
        assert_eq!(
            eni.net.addresses,
            ["10.0.1.5/24 brd 10.0.1.255 metric 1003"],
            "the address the fixture's ip prints"
        );
        let hop = |ip: [u8; 4], mac: [u8; 6]| (Ipv4Addr::from(ip), mac);
        assert_eq!(
            eni.next_hops,
            [
                hop([10, 0, 1, 9], [0x0a, 0, 0, 0, 1, 9]),
                hop([10, 0, 2, 7], [0x0a, 0, 0, 0, 1, 1]),
            ],
            "each peer's next hop, the second through the gateway"
        );
        assert_eq!(
            eni.net.routes,
            ["10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003"],
            "the route the fixture's ip prints"
        );
        named
    }

    /// Checks that every driver write in `entries` names a recorded device
    /// and was issued with a complete record of the pre-bind snapshot in
    /// place, published: a bind's writes follow the directory sync after
    /// its record's rename, and no write follows a record's unlink.
    fn writes_follow_the_record(&self, entries: &[Entry]) {
        let step = |name: &str| entries.contains(&Entry::Step(name.to_owned()));
        // A release finds its record published; a bind publishes its own.
        let mut published = !step("Rename");
        let (mut synced, mut renamed) = (false, false);
        for entry in entries {
            match entry {
                Entry::Step(at) if at == "FileSync" => synced = true,
                Entry::Step(at) if at == "Rename" => {
                    assert!(synced, "the record's file syncs before its rename");
                    (published, renamed) = (false, true);
                }
                Entry::Step(at) if at == "DirectorySync" && renamed => {
                    (published, renamed) = (true, false);
                }
                Entry::Step(at) if at == "Unlink" => published = false,
                _ => {}
            }
            if let Entry::Write {
                path,
                value,
                record,
            } = entry
            {
                assert!(
                    published,
                    "{path}={value} follows its record's directory sync"
                );
                let record = record
                    .as_ref()
                    .unwrap_or_else(|| panic!("{path}={value} has a record in place"));
                let named = self.names_the_snapshot(record);
                assert!(
                    named
                        .iter()
                        .any(|bdf| path.contains(bdf.as_str()) || value == bdf),
                    "a write names a device its record names: {path}={value}"
                );
            }
        }
    }

    /// Appends the case to the parent's case log, outside the repository,
    /// in one write: the cut, the kill, the deadline and recovery
    /// assumptions, the surviving state with the record's raw bytes, the
    /// fresh release's result, and every child's journal.
    fn log(&self, cut: &Cut, survivor: &str, record: Option<&[u8]>, release: &str) {
        let path = std::env::temp_dir().join(format!("bind-cuts-{}.log", std::process::id()));
        let hex: String = record.map_or_else(
            || "-".to_owned(),
            |bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        );
        let mut entry = format!(
            "cut={} kill=SIGKILL deadline={:?} assumptions=same-host-and-boot,approved-modules,free-locks,fixture-calls-succeed disposition={:?} survivor={survivor} record={hex} release={release}\n",
            cut.name, cut.deadline, cut.disposition
        );
        for child in 1..=self.children {
            let journal = self.fixture.root.join(format!("journal-{child}"));
            let text = fs::read_to_string(journal).unwrap_or_default();
            entry += &format!("  journal-{child}:\n");
            for line in text.lines() {
                entry += &format!("    {line}\n");
            }
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap()
            .write_all(entry.as_bytes())
            .unwrap();
    }
}

fn runs(entries: &[Entry]) -> Vec<&str> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Run(line) => Some(line.as_str()),
            Entry::Write { .. } | Entry::Step(_) => None,
        })
        .collect()
}

fn writes(entries: &[Entry]) -> usize {
    entries
        .iter()
        .filter(|entry| matches!(entry, Entry::Write { .. }))
        .count()
}

/// Checks the disposition `cut` declares, then a fresh release in a new
/// process against it.
fn converge(episode: &mut Episode, cut: &Cut, killed: &[Entry]) {
    converge_by(episode, cut, killed, Action::Release);
}

/// [`converge`], with the fresh child running `release`.
fn converge_by(episode: &mut Episode, cut: &Cut, killed: &[Entry], release: Action) {
    episode.writes_follow_the_record(killed);
    let record = fs::read(episode.record()).ok();
    let (survivor, expected) = match cut.disposition {
        Disposition::Unpublished => {
            assert_eq!(record, None, "{}: no record", cut.name);
            assert_eq!(writes(killed), 0, "{}: no driver write", cut.name);
            assert_eq!(episode.drivers(), episode.snapshot);
            ("no record, drivers unchanged", "Err(Mappings(Io(")
        }
        Disposition::Recorded => {
            let bytes = record
                .as_deref()
                .unwrap_or_else(|| panic!("{}: the record survives", cut.name));
            episode.names_the_snapshot(bytes);
            ("valid record", "Ok(())")
        }
        Disposition::Released => {
            assert_eq!(record, None, "{}: the record is removed", cut.name);
            assert_eq!(episode.drivers(), episode.snapshot, "{}", cut.name);
            assert!(
                runs(killed)
                    .contains(&format!("ip link set dev if6 mtu {}", episode.mtu.trim()).as_str()),
                "{}: the killed child restored the network before the unlink",
                cut.name
            );
            ("restored, no record", "Err(Mappings(Io(")
        }
    };
    let (result, released) = episode.complete(release, cut.deadline);
    assert!(
        result.starts_with(expected),
        "{}: a fresh release returns {expected}..: {result}",
        cut.name
    );
    episode.writes_follow_the_record(&released);
    assert_eq!(
        episode.drivers(),
        episode.snapshot,
        "{}: restored",
        cut.name
    );
    assert!(!episode.record().exists(), "{}: no record left", cut.name);
    match cut.disposition {
        Disposition::Recorded => {
            let runs = runs(&released);
            assert_eq!(
                runs,
                [
                    "ip -o link show",
                    format!("ip link set dev if6 mtu {}", episode.mtu.trim()).as_str(),
                    "ip link set dev if6 up",
                    "ip addr replace 10.0.1.5/24 brd 10.0.1.255 metric 1003 dev if6",
                    "ip route replace 10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003 dev if6",
                ],
                "{}: the fresh release replays the recorded network state on the ENI alone",
                cut.name
            );
        }
        Disposition::Unpublished | Disposition::Released => {
            assert!(
                result.contains("NotFound"),
                "{}: the missing record refuses: {result}",
                cut.name
            );
            assert_eq!(writes(&released), 0, "{}: no write", cut.name);
            assert!(runs(&released).is_empty(), "{}: no command", cut.name);
        }
    }
    episode.log(cut, survivor, record.as_deref(), &result);
}

/// Kills a child at `name`'s cut and checks that a fresh release converges.
/// A release cut runs after a child bound the devices to its end.
fn witness(name: &str) {
    witness_after(name, true);
}

/// The check of [`witness`], with the bind a release cut follows run only
/// when `bind_first`.
fn witness_after(name: &str, bind_first: bool) {
    let cut = cut_named(name);
    let mut episode = Episode::new();
    if cut.action == Action::Release && bind_first {
        let (result, bound) = episode.complete(Action::Bind, cut.deadline);
        assert_eq!(result, "Ok(())");
        episode.writes_follow_the_record(&bound);
    }
    let killed = episode.kill_at(cut);
    if cut.name == "bind/next-hop-flush" {
        assert!(
            runs(&killed).contains(&"ip -4 neigh flush to 10.0.1.9 dev ens6"),
            "the cut falls after the batch's first flush"
        );
    }
    converge(&mut episode, cut, &killed);
}

/// The frozen matrix declares each cut once and a cut for each
/// disposition; each cut's own test below witnesses it.
#[test]
fn the_cut_matrix_is_frozen_and_declares_every_disposition() {
    declares_each_cut_once_and_every_disposition(&CUTS);
}

/// The checks of [`the_cut_matrix_is_frozen_and_declares_every_disposition`],
/// run against `cuts`.
fn declares_each_cut_once_and_every_disposition(cuts: &[Cut]) {
    let names: Vec<&str> = cuts.iter().map(|cut| cut.name).collect();
    for (at, name) in names.iter().enumerate() {
        assert!(!names[..at].contains(name), "{name} is declared once");
    }
    for disposition in [
        Disposition::Unpublished,
        Disposition::Recorded,
        Disposition::Released,
    ] {
        assert!(
            cuts.iter().any(|cut| cut.disposition == disposition),
            "{disposition:?} has a cut"
        );
    }
}

/// A bind killed after its controller moved leaves a record; a release
/// killed in the middle of its network batch leaves it too; a third child,
/// a fresh release, then restores every device and removes the record.
#[test]
fn a_release_killed_in_its_network_batch_after_a_killed_bind_converges() {
    let mut episode = Episode::new();
    let killed = episode.kill_at(cut_named("bind/controller-bind"));
    episode.writes_follow_the_record(&killed);
    episode.names_the_snapshot(&fs::read(episode.record()).unwrap());
    let batch = cut_named("release/network-batch");
    let interrupted = episode.kill_at(batch);
    converge(&mut episode, batch, &interrupted);
}

#[test]
fn a_cut_child_left_running_exits_once_its_lifetime_expires() {
    let mut episode = Episode::new();
    episode.lifetime = Duration::from_millis(200);
    let cut = cut_named("bind/record-create");
    let (mut child, _) = episode.spawn(cut.action, Some(cut));
    let until = Instant::now() + cut.deadline;
    assert!(
        std::iter::from_fn(|| child.next_report(until)).any(|report| report == reached(cut.name)),
        "{} is reached",
        cut.name
    );
    let outcome = child.finish(Instant::now() + Duration::from_secs(10));
    assert!(
        matches!(&outcome, Outcome::Failed { status, .. } if status.code() == Some(STRAYED)),
        "the child left running exits {STRAYED} by itself: {outcome:?}"
    );
}

/// Every row of [`CUTS`] has exactly one `#[test]` function in this file
/// whose body is `witness` of that row, so a cut added without a witness,
/// or a witness deleted, fails here.
#[test]
fn every_frozen_cut_has_its_witness() {
    let source = include_str!("cut_tests.rs");
    for cut in &CUTS {
        let body = format!("() {{\n    witness(\"{}\");\n}}", cut.name);
        let witnesses: Vec<&str> = source
            .match_indices(&body)
            .map(|(at, _)| &source[..at])
            .collect();
        assert_eq!(witnesses.len(), 1, "{} has one witness", cut.name);
        let header = witnesses[0].rsplit_once("\n#[test]\nfn ");
        assert!(
            header.is_some_and(|(above, name)| !name.contains('\n')
                && !above.ends_with("#[ignore]")
                && !above.ends_with(")]")),
            "{}'s witness is a test function that runs",
            cut.name
        );
    }
}

#[test]
fn a_bind_killed_in_its_next_hop_flush_leaves_no_record() {
    witness("bind/next-hop-flush");
}

#[test]
fn a_bind_killed_at_its_record_create_leaves_no_record() {
    witness("bind/record-create");
}

#[test]
fn a_bind_killed_at_its_record_rename_leaves_no_record() {
    witness("bind/record-rename");
}

#[test]
fn a_bind_killed_after_its_record_rename_leaves_a_record_release_restores() {
    witness("bind/record-renamed");
}

#[test]
fn a_bind_killed_before_its_first_driver_write_leaves_a_record_release_restores() {
    witness("bind/first-driver-write");
}

#[test]
fn a_bind_killed_after_the_controller_override_leaves_a_record_release_restores() {
    witness("bind/controller-override");
}

#[test]
fn a_bind_killed_after_the_controller_unbind_leaves_a_record_release_restores() {
    witness("bind/controller-unbind");
}

#[test]
fn a_bind_killed_after_the_controller_bind_leaves_a_record_release_restores() {
    witness("bind/controller-bind");
}

#[test]
fn a_bind_killed_after_the_eni_override_leaves_a_record_release_restores() {
    witness("bind/eni-override");
}

#[test]
fn a_bind_killed_after_the_eni_unbind_leaves_a_record_release_restores() {
    witness("bind/eni-unbind");
}

#[test]
fn a_bind_killed_after_the_eni_bind_leaves_a_record_release_restores() {
    witness("bind/eni-bind");
}

#[test]
fn a_bind_killed_after_it_returned_leaves_a_record_release_restores() {
    witness("bind/returned");
}

#[test]
fn a_rollback_killed_after_the_controller_unbind_leaves_a_record_release_restores() {
    witness("rollback/controller-unbind");
}

#[test]
fn a_rollback_killed_after_the_controller_override_leaves_a_record_release_restores() {
    witness("rollback/controller-override");
}

#[test]
fn a_rollback_killed_after_the_controller_bind_leaves_a_record_release_restores() {
    witness("rollback/controller-bind");
}

#[test]
fn a_rollback_killed_after_the_controller_override_clear_leaves_a_record_release_restores() {
    witness("rollback/controller-override-cleared");
}

#[test]
fn a_rollback_killed_after_the_eni_override_clear_leaves_a_record_release_restores() {
    witness("rollback/eni-override-cleared");
}

#[test]
fn a_rollback_killed_in_its_network_batch_leaves_a_record_release_restores() {
    witness("rollback/network-batch");
}

#[test]
fn a_rollback_killed_at_its_unlink_leaves_a_record_release_restores() {
    witness("rollback/unlink");
}

#[test]
fn a_rollback_killed_after_its_unlink_leaves_nothing_a_fresh_release_writes() {
    witness("rollback/unlinked");
}

#[test]
fn a_release_killed_before_its_first_restore_write_converges_on_a_fresh_release() {
    witness("release/first-restore-write");
}

#[test]
fn a_release_killed_after_the_controller_unbind_converges_on_a_fresh_release() {
    witness("release/controller-unbind");
}

#[test]
fn a_release_killed_after_the_controller_override_converges_on_a_fresh_release() {
    witness("release/controller-override");
}

#[test]
fn a_release_killed_after_the_controller_bind_converges_on_a_fresh_release() {
    witness("release/controller-bind");
}

#[test]
fn a_release_killed_after_the_eni_unbind_converges_on_a_fresh_release() {
    witness("release/eni-unbind");
}

#[test]
fn a_release_killed_after_the_eni_override_converges_on_a_fresh_release() {
    witness("release/eni-override");
}

#[test]
fn a_release_killed_after_the_controller_override_clear_converges_on_a_fresh_release() {
    witness("release/controller-override-cleared");
}

#[test]
fn a_release_killed_with_the_controller_restored_converges_on_a_fresh_release() {
    witness("release/controller-restored");
}

#[test]
fn a_release_killed_after_the_eni_override_clear_converges_on_a_fresh_release() {
    witness("release/eni-override-cleared");
}

#[test]
fn a_release_killed_after_the_eni_bind_converges_on_a_fresh_release() {
    witness("release/eni-bind");
}

#[test]
fn a_release_killed_in_its_network_batch_converges_on_a_fresh_release() {
    witness("release/network-batch");
}

#[test]
fn a_release_killed_at_its_unlink_converges_on_a_fresh_release() {
    witness("release/unlink");
}

#[test]
fn a_release_killed_after_its_unlink_leaves_nothing_a_fresh_release_writes() {
    witness("release/unlinked");
}

#[test]
fn a_release_killed_after_it_returned_leaves_nothing_a_fresh_release_writes() {
    witness("release/returned");
}

/// A broken binder: it moves the controller to `vfio-pci` through the
/// override, unbind and bind writes the production move makes, and only
/// then publishes `mappings`, the record the production bind publishes.
fn bind_moving_the_controller_before_its_record(binder: &Binder<FakeKernel>, mappings: &Mappings) {
    let pci = binder.host.pci(BDF);
    binder
        .kernel
        .write(&pci.join("driver_override"), VFIO)
        .unwrap();
    binder
        .kernel
        .write(&pci.join("driver/unbind"), BDF)
        .unwrap();
    binder
        .kernel
        .write(&binder.host.bind_file(VFIO), BDF)
        .unwrap();
    mappings
        .write(&mappings_path(&binder.state_dir))
        .expect("the late record publishes");
}

/// The production bind, run in this process over a journaled kernel, passes
/// the write-order check the cut cases apply to each child's journal: the
/// sibling of the control below.
#[test]
fn a_production_bind_in_one_process_passes_the_write_order_check() {
    let episode = Episode::new();
    let path = episode.fixture.root.join("journal-in-process");
    let binder = journaled_binder(&episode.fixture.root, &path, None);
    bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).expect("the production bind succeeds");
    let entries = journal(&path);
    assert!(writes(&entries) > 0, "the bind's driver writes are logged");
    episode.writes_follow_the_record(&entries);
}

/// A binder that moves the controller before it publishes its record fails
/// the record's own write-order check, [`Episode::writes_follow_the_record`],
/// at its first driver write. The record it publishes late is the one a
/// production bind on a twin fixture published.
#[test]
#[should_panic(expected = "follows its record's directory sync")]
fn negative_control_a_binder_moving_the_controller_before_its_record_fails_the_write_order_check() {
    let twin = Episode::new();
    let journaled = journaled_binder(
        &twin.fixture.root,
        &twin.fixture.root.join("journal-twin"),
        None,
    );
    let mappings = bind_eni(&journaled, Some(VOLUME), &FakeMetadata::new())
        .expect("the production bind succeeds");
    let episode = Episode::new();
    let path = episode.fixture.root.join("journal-in-process");
    let binder = journaled_binder(&episode.fixture.root, &path, None);
    bind_moving_the_controller_before_its_record(&binder, &mappings);
    episode.writes_follow_the_record(&journal(&path));
}

/// A release that removes its record without restoring a device fails the
/// convergence check every release cut applies, [`converge`]'s, run here
/// through [`converge_by`] with that broken release in the fresh child.
/// The cut is `release/controller-bind`, so the ENI stays on `vfio-pci`.
#[test]
#[should_panic(expected = "release/controller-bind: restored")]
fn negative_control_a_release_discarding_its_record_unrestored_fails_convergence() {
    let cut = cut_named("release/controller-bind");
    let mut episode = Episode::new();
    let (result, bound) = episode.complete(Action::Bind, cut.deadline);
    assert_eq!(result, "Ok(())");
    episode.writes_follow_the_record(&bound);
    let killed = episode.kill_at(cut);
    converge_by(&mut episode, cut, &killed, Action::DiscardingRelease);
}

/// A matrix that declares one cut twice fails the frozen-matrix check,
/// [`declares_each_cut_once_and_every_disposition`], at its declared-once
/// assertion.
#[test]
#[should_panic(expected = "bind/record-create is declared once")]
fn negative_control_a_matrix_declaring_a_cut_twice_fails_the_frozen_matrix_check() {
    let create = || {
        cut(
            "bind/record-create",
            Action::Bind,
            Site::Record(RecordStep::Create, 1),
            Disposition::Unpublished,
        )
    };
    declares_each_cut_once_and_every_disposition(&[create(), create()]);
}

/// A matrix with no cut of the `Released` disposition fails the
/// frozen-matrix check at its every-disposition assertion.
#[test]
#[should_panic(expected = "Released has a cut")]
fn negative_control_a_matrix_without_a_released_cut_fails_the_frozen_matrix_check() {
    declares_each_cut_once_and_every_disposition(&[
        cut(
            "bind/record-create",
            Action::Bind,
            Site::Record(RecordStep::Create, 1),
            Disposition::Unpublished,
        ),
        cut(
            "bind/returned",
            Action::Bind,
            Site::Returned,
            Disposition::Recorded,
        ),
    ]);
}

/// A release cut witnessed without the bind it follows is missing evidence.
/// The child's release refuses on the missing record before its first
/// restore write, so it never reaches the cut's site, and the witness fails
/// in [`Episode::kill_at`] at the unreached cut.
#[test]
#[should_panic(expected = "release/first-restore-write was not reached within")]
fn negative_control_a_release_cut_witnessed_without_its_bind_is_missing_evidence() {
    witness_after("release/first-restore-write", false);
}
