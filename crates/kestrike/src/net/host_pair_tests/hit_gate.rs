//! The open-loop hit gate's client cell: GETs of the host pair owner's records leave on a
//! fixed schedule of intended send times, and each sample runs from its intended send to the
//! client turn that decided the GET. `scripts/hit-gate.py` judges the samples.
//!
//! - INTENDED-SEND: request `i` is intended at `start + floor(i * 1_000_000 / rate)` microseconds;
//!   a GET the client admits later, behind its request slots or receive buffers, keeps its
//!   intended time, so client queueing counts in its latency. A sample also records its first
//!   attempt, the first pass of the loop at or after the intended time, so the generator's own
//!   lateness is read apart from the wait for a slot.
//! - VERIFIED-END: a sample ends at the end of the client turn whose poll decided the GET, the
//!   first turn after which the client reports its outcome; the client decides a GET complete
//!   only after its own identity, length and integrity checks, and the cell compares every
//!   fragment of a complete GET with the record it generates itself, so a complete GET with
//!   other bytes fails the cell.
//! - SOURCE-TAG: each sample carries its stratum (hit, miss, refused or error) and the label
//!   [`SOURCE`] of the run's one routed owner. Every sample carries that label, so the cell
//!   observes no residual-owner traffic.
//!
//! The cell runs as the client role of the `hit-gate` profile beside
//! `net::host_pair_tests::the_owner_serves_the_volume`, with the host pair's inputs and
//! `KESTRIKE_HIT_WORKLOAD` (a name of [`WORKLOADS`]), `KESTRIKE_HIT_RATE` (GETs per
//! second, at most 1,000,000, so intended times strictly increase), `KESTRIKE_HIT_REQUESTS`
//! (1 to [`MAX_REQUESTS`]), `KESTRIKE_HIT_SEED` (the seed `scripts/hit-gate.py schedule`
//! prints for the campaign), `KESTRIKE_HIT_PREVIOUS` (the SHA-256 the previous run of the
//! campaign's cell printed, or `none` for its first run) and `KESTRIKE_HIT_SAMPLES`, an
//! absolute path at which no entry exists, in a directory whose every ancestor only root or the
//! running user can write. The cell checks that directory and creates the file, refusing an
//! existing entry or a link at the path, before it brings up a device. It writes one header line
//! with the plan and the client host's wall-clock time when its sample clock started, in
//! milliseconds, then one line
//! `[intended_us, attempted_us, admitted_us, end_us, record, stratum, source]` per
//! GET in request order. After it prints the samples' digest, the cell goes quiet for one GET, as
//! the owner's quiet drain check needs, and keeps GETs in flight until the owner's close ends
//! one, as the owner's close check needs.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::*;
use crate::net::ena_hardware_tests::hex;
use crate::storage::seeded::SplitMix64;

/// The most GETs one run plans, which bounds the samples the cell reserves before it brings up a
/// device.
pub(super) const MAX_REQUESTS: u64 = 1 << 22;

/// The highest rate the cell accepts, at which consecutive intended times differ by one microsecond.
const MAX_RATE: u64 = 1_000_000;

/// The label of the run's one routed owner, its index in the client's route.
pub(super) const SOURCE: usize = 0;

/// A request mix over [`RECORDS`]: request `i` reads record `n` with probability
/// `weights[n] / sum(weights)`.
pub(super) struct Workload {
    pub(super) name: &'static str,
    pub(super) weights: [u64; RECORDS.len()],
}

/// The workloads the cell runs, which the manifest's `qualification.workloads` repeats: every
/// record at equal weight, and the large-object workload of the 241,011-byte record alone.
pub(super) const WORKLOADS: [Workload; 2] = [
    Workload {
        name: "request-weighted",
        weights: [1, 1, 1, 1],
    },
    Workload {
        name: "large-object",
        weights: [0, 0, 1, 0],
    },
];

/// One run's schedule: `requests` GETs at `rate` per second, records drawn from `workload` by `seed`.
pub(super) struct Plan {
    pub(super) workload: &'static Workload,
    pub(super) rate: u64,
    pub(super) requests: u64,
    pub(super) seed: u64,
    /// The SHA-256 the previous run of the cell printed, or `none`, which chains a cell's runs in
    /// the order they ran.
    pub(super) previous: String,
    /// The client host's wall clock when the sample clock started, a diagnostic the judge does
    /// not order by.
    pub(super) started_unix_ms: u64,
}

/// How one GET ended, as the judge strata name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stratum {
    Hit,
    Miss,
    Refused,
    Error,
}

impl Stratum {
    fn of(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Complete => Self::Hit,
            Outcome::Missing => Self::Miss,
            Outcome::Pressure(_) => Self::Refused,
            Outcome::Failed(_) | Outcome::Incomplete(_) => Self::Error,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Refused => "refused",
            Self::Error => "error",
        }
    }
}

/// One GET's sample. `attempted_us` is the first pass of the loop at or after the intended time,
/// and `admitted_us` the pass at which the client admitted the GET. `decided_us` is the client's
/// own decision time, the start of the deciding poll; the samples file records `end_us`, the end
/// of that turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sample {
    pub(super) intended_us: u64,
    pub(super) attempted_us: u64,
    pub(super) admitted_us: u64,
    pub(super) end_us: u64,
    pub(super) decided_us: u64,
    pub(super) record: usize,
    pub(super) stratum: Stratum,
}

impl Plan {
    /// The plan of `workload` at `rate` for `requests` GETs, or the reason the judge could not
    /// bind it: an unknown workload, a rate outside 1 to [`MAX_RATE`], a request
    /// count outside 1 to [`MAX_REQUESTS`], or a `previous` other than `none` or a lowercase SHA-256.
    pub(super) fn checked(
        workload: &str,
        rate: u64,
        requests: u64,
        seed: u64,
        previous: String,
    ) -> Result<Self, String> {
        let workload = WORKLOADS
            .iter()
            .find(|known| known.name == workload)
            .ok_or_else(|| format!("no workload is named {workload}"))?;
        if !(1..=MAX_RATE).contains(&rate) {
            return Err(format!("rate {rate} is outside 1 to {MAX_RATE}"));
        }
        if !(1..=MAX_REQUESTS).contains(&requests) {
            return Err(format!(
                "{requests} requests are outside 1 to {MAX_REQUESTS}"
            ));
        }
        let digest = previous.len() == 64
            && previous
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if previous != "none" && !digest {
            return Err(format!(
                "previous {previous:?} is neither none nor a SHA-256"
            ));
        }
        Ok(Self {
            workload,
            rate,
            requests,
            seed,
            previous,
            started_unix_ms: unix_ms(),
        })
    }

    fn from_env() -> Self {
        let var = |name: &str| {
            std::env::var(name).unwrap_or_else(|_| panic!("set {name}; see the module docs"))
        };
        let number = |name: &str| {
            var(name)
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("{name} is a number"))
        };
        Self::checked(
            &var("KESTRIKE_HIT_WORKLOAD"),
            number("KESTRIKE_HIT_RATE"),
            number("KESTRIKE_HIT_REQUESTS"),
            number("KESTRIKE_HIT_SEED"),
            var("KESTRIKE_HIT_PREVIOUS"),
        )
        .unwrap_or_else(|reason| panic!("the KESTRIKE_HIT_* plan is refused: {reason}"))
    }

    pub(super) fn intended_us(&self, start_us: u64, i: u64) -> u64 {
        start_us + u64::try_from(u128::from(i) * 1_000_000 / u128::from(self.rate)).unwrap()
    }

    /// Request `i`'s record: the first draw of [`SplitMix64`] seeded with `seed + i`, modulo the
    /// weight sum, names the record whose cumulative weight range holds it.
    pub(super) fn record(&self, i: u64) -> usize {
        let mut draw = SplitMix64::new(self.seed.wrapping_add(i))
            .below(self.workload.weights.iter().sum::<u64>());
        for (n, &weight) in self.workload.weights.iter().enumerate() {
            if draw < weight {
                return n;
            }
            draw -= weight;
        }
        unreachable!("a draw below the weight sum lies in one record's range")
    }

    /// Writes the samples file to `out`, the plan's header line then one line per sample, and
    /// returns the lowercase SHA-256 of the bytes written.
    ///
    /// # Errors
    ///
    /// When a write to `out` fails.
    pub(super) fn write_samples(
        &self,
        out: &mut impl std::io::Write,
        samples: &[Sample],
    ) -> std::io::Result<String> {
        let header = serde_json::json!({
            "workload": self.workload.name,
            "records": RECORDS,
            "weights": self.workload.weights,
            "rate": self.rate,
            "requests": self.requests,
            "seed": self.seed,
            "previous": self.previous,
            "slots": SLOTS,
            "source": SOURCE,
            "started_unix_ms": self.started_unix_ms,
        });
        let mut hasher = Sha256::new();
        let mut line = format!("{header}\n");
        hasher.update(line.as_bytes());
        out.write_all(line.as_bytes())?;
        for sample in samples {
            line.clear();
            writeln!(
                line,
                "[{},{},{},{},{},\"{}\",{SOURCE}]",
                sample.intended_us,
                sample.attempted_us,
                sample.admitted_us,
                sample.end_us,
                sample.record,
                sample.stratum.name(),
            )
            .unwrap();
            hasher.update(line.as_bytes());
            out.write_all(line.as_bytes())?;
        }
        Ok(hex(&hasher.finalize()))
    }
}

fn unix_ms() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    u64::try_from(since.expect("the clock is past the epoch").as_millis()).unwrap()
}

/// Checks that only root or the running user can write `path`'s directory and each of its
/// ancestors, as [`crate::bind::private_state_dir`] defines it, so no other user can replace an
/// entry on the path between this check and the file's creation.
///
/// # Errors
///
/// The first directory on the path that fails the check.
fn private_parent(path: &Path) -> Result<(), std::path::PathBuf> {
    let parent = path.parent().unwrap_or(path);
    // SAFETY: reads the effective user ID.
    crate::bind::private_state_dir(parent, unsafe { libc::geteuid() })
}

/// Creates the samples file at `path`, readable and writable by its owner only. The open fails
/// for an existing entry, a link at the path included, so an earlier run's file is never
/// truncated and no link is followed.
///
/// # Errors
///
/// As for the open.
fn create_samples(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// A GET in flight: its id, record, intended, first-attempt and admitted times, the end of the
/// turn that decided it and the client's own decision time once one did, how many bytes it took,
/// and whether every byte matched its record.
struct Flight {
    id: RequestId,
    record: usize,
    intended_us: u64,
    attempted_us: u64,
    admitted_us: u64,
    decided: Option<(u64, u64)>,
    taken: usize,
    exact: bool,
}

/// Runs one client turn, then stamps every GET in `flights` that the turn decided with the
/// turn's end and the client's decision time.
fn turn<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    flights: &mut [Flight],
) {
    pump.turn(client);
    let turn_end_us = pump.now_us();
    for flight in flights.iter_mut().filter(|f| f.decided.is_none()) {
        if let Some(terminal) = client.terminal(flight.id) {
            flight.decided = Some((turn_end_us, terminal.decided_us));
        }
    }
}

/// Runs `plan` against the routed owner and appends one sample per GET to `samples`, in request
/// order. Each pass first stamps every GET whose intended time has passed with the pass's time,
/// its first attempt, then admits the stamped GETs in order as far as the client admits them,
/// then polls once, stamps the GETs that poll decided and settles them. A GET that waits behind
/// the client's slots keeps the stamp of the pass that first reached it. The stamps of the GETs
/// not yet admitted are reserved for the whole plan before the first intended send. The
/// expected records are generated before the first intended send, and each fragment is compared
/// in place with its record's bytes, so no GET's latency includes a record's generation or copy.
/// The final sort reorders in place.
///
/// # Panics
///
/// When the client refuses a GET for a cause other than pressure, a complete GET delivers
/// bytes other than its record, or a terminal observation loses the intended time.
pub(super) fn open_loop<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    plan: &Plan,
    wait_us: u64,
    samples: &mut Vec<Sample>,
) {
    let expected: Vec<Vec<u8>> = (0..RECORDS.len()).map(record).collect();
    let mut due = VecDeque::with_capacity(usize::try_from(plan.requests).unwrap());
    let start_us = pump.now_us();
    let (mut next, mut reached, mut flights) = (0, 0, Vec::<Flight>::new());
    while next < plan.requests || !flights.is_empty() {
        let now = pump.now_us();
        while reached < plan.requests && plan.intended_us(start_us, reached) <= now {
            due.push_back(now);
            reached += 1;
        }
        while let Some(&attempted_us) = due.front() {
            let (record, intended_us) = (plan.record(next), plan.intended_us(start_us, next));
            let key = key(u8::try_from(record).unwrap() + 1);
            match client.get_intended(key, 64, BODY_CAP as u32, intended_us, now, wait_us) {
                Ok(id) => flights.push(Flight {
                    id,
                    record,
                    intended_us,
                    attempted_us,
                    admitted_us: now,
                    decided: None,
                    taken: 0,
                    exact: true,
                }),
                Err(GetRefused::RequestPressure | GetRefused::ReceivePressure) => break,
                Err(refused) => panic!("GET {next} refused {refused:?}"),
            }
            due.pop_front();
            next += 1;
        }
        turn(client, pump, &mut flights);
        let mut i = 0;
        while i < flights.len() {
            let flight = &mut flights[i];
            while let Some(fragment) = client.take(flight.id) {
                assert_eq!(fragment.offset(), flight.taken as u64, "in order");
                let bytes = fragment.bytes();
                flight.exact &= expected[flight.record]
                    .get(flight.taken..flight.taken + bytes.len())
                    == Some(bytes);
                flight.taken += bytes.len();
            }
            let Some((end_us, decided_us)) = flight.decided else {
                i += 1;
                continue;
            };
            let flight = flights.swap_remove(i);
            let terminal = client.terminal(flight.id).expect("a decided GET");
            assert_eq!(
                terminal.intended_us, flight.intended_us,
                "the terminal keeps the intended send"
            );
            let stratum = Stratum::of(terminal.outcome);
            if stratum == Stratum::Hit {
                assert!(
                    flight.exact && flight.taken == expected[flight.record].len(),
                    "a hit's bytes are its record"
                );
            }
            while !client.retire(flight.id) {
                turn(client, pump, &mut flights);
            }
            samples.push(Sample {
                intended_us: flight.intended_us,
                attempted_us: flight.attempted_us,
                admitted_us: flight.admitted_us,
                end_us,
                decided_us,
                record: flight.record,
                stratum,
            });
        }
    }
    samples.sort_unstable_by_key(|sample| sample.intended_us);
}

#[test]
#[ignore = "needs the host pair's devices bound by kestrike-bind, named by KESTRIKE_MAPPINGS, and the KESTRIKE_HIT_* plan"]
fn the_client_drives_the_open_loop_hit_gate() {
    let mut plan = Plan::from_env();
    let path = std::env::var("KESTRIKE_HIT_SAMPLES")
        .expect("set KESTRIKE_HIT_SAMPLES; see the module docs");
    let path = Path::new(&path);
    assert!(
        path.is_absolute(),
        "KESTRIKE_HIT_SAMPLES is an absolute path"
    );
    private_parent(path).unwrap_or_else(|directory| {
        panic!("{directory:?} on the samples path is writable by another user")
    });
    let file = create_samples(path).expect("the samples file is created new");
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(usize::try_from(plan.requests).unwrap())
        .expect("the samples fit in memory");
    let (mappings, _lock) = mappings();
    dataplane!(mappings, env, arena, registration, view, pools, port);
    let burst = over(
        port,
        route(&mappings, CLIENT_PORT, &[(peer(), OWNER_PORT)]),
        &pools,
        &registration,
    );
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 24)).unwrap();
    let mut pump = Wall::new();
    plan.started_unix_ms = unix_ms();
    let mut client = client(
        client_index(),
        &view,
        &releases,
        Box::default(),
        burst,
        &mut pump,
    )
    .map_err(|_| "no session")
    .expect("the session opened");
    open_loop(&mut client, &mut pump, &plan, WAIT_US, &mut samples);
    let mut out = std::io::BufWriter::new(file);
    let digest = plan
        .write_samples(&mut out, &samples)
        .expect("the samples file is written");
    let file = out.into_inner().expect("the samples file is flushed");
    file.sync_all().expect("the samples file is synced");
    let hits = samples
        .iter()
        .filter(|sample| sample.stratum == Stratum::Hit)
        .count();
    eprintln!(
        "observe: hit-gate samples {} hits {hits} sha256 {digest}",
        samples.len()
    );
    abandon(&mut client, &mut pump, WAIT_US);
    let n = 2;
    until_closed(&mut client, &mut pump, key(n as u8 + 1), 64, &record(n));
    let (report, burst) = client.close(pump.now_us());
    eprintln!("close {report:?}");
    let _undone = teardown(burst.into_port(), pools, registration, &arena);
    finish(env);
    drop(view);
    release(arena);
}

/// Draws follow the weights: a zero-weight record is never read, and over 4,000 draws each
/// record of positive weight takes strictly between three quarters and five quarters of its
/// expected share. The draws and intended times pinned here are the ones
/// `scripts/test-hit-gate.py` pins for the judge, a seed whose `seed + i` wraps past 2^64
/// included.
#[test]
fn the_schedule_draws_records_by_the_workload_weights() {
    for workload in &WORKLOADS {
        let plan = Plan::checked(workload.name, 1_000, 4_000, 7, "none".into()).unwrap();
        let mut counts = [0u64; RECORDS.len()];
        for i in 0..plan.requests {
            counts[plan.record(i)] += 1;
        }
        for (n, &count) in counts.iter().enumerate() {
            let share = workload.weights[n] * plan.requests / workload.weights.iter().sum::<u64>();
            assert!(
                (share == 0 && count == 0) || (count * 4 > share * 3 && count * 4 < share * 5),
                "{} record {n}: {count} draws for a share of {share}",
                workload.name
            );
        }
    }
    let draws = |seed: u64| {
        let plan = Plan::checked("request-weighted", 3, 12, seed, "none".into()).unwrap();
        (0..12).map(|i| plan.record(i)).collect::<Vec<_>>()
    };
    assert_eq!(draws(7), [3, 2, 0, 2, 1, 3, 3, 2, 1, 3, 3, 2]);
    assert_eq!(draws(u64::MAX - 4), [2, 2, 1, 1, 0, 3, 1, 2, 1, 2, 2, 0]);
    let plan = Plan::checked("request-weighted", 3, 5, 7, "none".into()).unwrap();
    assert_eq!(
        (0..5).map(|i| plan.intended_us(0, i)).collect::<Vec<_>>(),
        [0, 333_333, 666_666, 1_000_000, 1_333_333],
        "intended times at 3 per second floor each interval"
    );
}

/// The plan refuses every value the judge cannot bind before any device work.
#[test]
fn the_plan_refuses_values_the_judge_cannot_bind() {
    let plan = |workload: &str, rate, requests, previous: &str| {
        Plan::checked(workload, rate, requests, 1, previous.into()).map(drop)
    };
    assert_eq!(plan("request-weighted", 1_000, 10, "none"), Ok(()));
    assert_eq!(
        plan("large-object", MAX_RATE, MAX_REQUESTS, &"ab".repeat(32)),
        Ok(())
    );
    for (workload, rate, requests, previous) in [
        ("small-object", 1_000, 10, "none"),
        ("request-weighted", 0, 10, "none"),
        ("request-weighted", MAX_RATE + 1, 10, "none"),
        ("request-weighted", 1_000, 0, "none"),
        ("request-weighted", 1_000, MAX_REQUESTS + 1, "none"),
        ("request-weighted", 1_000, 10, "NONE"),
        ("request-weighted", 1_000, 10, &"AB".repeat(32)),
        ("request-weighted", 1_000, 10, &"ab".repeat(31)),
    ] {
        assert!(
            plan(workload, rate, requests, previous).is_err(),
            "{workload} {rate} {requests} {previous}"
        );
    }
}

/// Every client outcome maps to the stratum name the judge reads.
#[test]
fn every_outcome_maps_to_the_judges_stratum_name() {
    for (outcome, name) in [
        (Outcome::Complete, "hit"),
        (Outcome::Missing, "miss"),
        (Outcome::Pressure(Status::RequestPressure), "refused"),
        (Outcome::Failed(Status::TimedOut), "error"),
        (Outcome::Incomplete(Status::OwnerUnavailable), "error"),
    ] {
        assert_eq!(Stratum::of(outcome).name(), name, "{outcome:?}");
    }
}

/// The samples file is created only where no entry exists: a second creation, a live link and
/// a dangling link at the path are refused, and neither link's target is written or created.
/// A directory another user can write is refused before the file is created.
#[test]
fn the_samples_file_is_created_new_and_never_through_a_link() {
    let dir = std::env::temp_dir().join(format!("hit-gate-samples-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("run.samples");
    drop(create_samples(&path).expect("a new path is created"));
    assert!(
        create_samples(&path).is_err(),
        "an existing file is refused"
    );
    let (target, live, dangling) = (
        dir.join("target"),
        dir.join("live.samples"),
        dir.join("dangling.samples"),
    );
    std::fs::write(&target, "kept").unwrap();
    std::os::unix::fs::symlink(&target, &live).unwrap();
    std::os::unix::fs::symlink(dir.join("absent"), &dangling).unwrap();
    assert!(create_samples(&live).is_err(), "a live link is refused");
    assert!(
        create_samples(&dangling).is_err(),
        "a dangling link is refused"
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept");
    assert!(
        !dir.join("absent").exists(),
        "no file appears at a link's target"
    );
    let shared = dir.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::set_permissions(&shared, std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
    assert_eq!(
        private_parent(&shared.join("run.samples")),
        Err(shared),
        "a directory others can write is refused at that directory"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The cell's workloads are the manifest's: `qualification.workloads` in
/// `scripts/hardware-profiles.json` names each workload with these records and weights, which
/// the judge compares with every samples header.
#[test]
fn the_manifest_declares_the_cells_workloads() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/hardware-profiles.json"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let declared = manifest["qualification"]["workloads"]
        .as_object()
        .expect("the manifest declares workloads");
    assert_eq!(declared.len(), WORKLOADS.len());
    for workload in &WORKLOADS {
        let entry = &declared[workload.name];
        assert_eq!(
            entry["records"],
            serde_json::json!(RECORDS),
            "{}",
            workload.name
        );
        assert_eq!(
            entry["weights"],
            serde_json::json!(workload.weights),
            "{}",
            workload.name
        );
    }
}

/// Runs `requests` GETs of `workload` at 1,000,000 per second over a simulated owner that
/// published `published`, each `(n, bytes)` stored under record `n`'s key and metadata length,
/// and returns the run's start, its plan and its samples.
fn simulated_run(
    published: &[(usize, Vec<u8>)],
    workload: &'static Workload,
    requests: u64,
) -> (u64, Plan, Vec<Sample>) {
    let storage = heap_storage_on(SIM_PAYLOAD, BODY_CAP);
    let buffers = arena_on(TestPlatform::heap(4096), 16, 8);
    let (receive, client_pool) = (pool(), pool());
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let objects: Vec<_> = published
        .iter()
        .map(|(n, bytes)| (key(*n as u8 + 1), RECORDS[*n].1, bytes.as_slice()))
        .collect();
    let (client_end, owner_end, net) = network(64, 8384, SESSION, [Faults::default(); 2]);
    let (mut owner, control) = start(&storage, &buffers, &receive, &objects, vec![owner_end]);
    let mut pump = Simulated {
        owner: &mut owner,
        control: &control,
        net,
        held: 0,
        turn: 0,
        quiet: QuietDrains::default(),
        corpus: Corpus::new(),
    };
    let mut client = client(
        0,
        &client_pool,
        &releases,
        Box::default(),
        client_end,
        &mut pump,
    )
    .map_err(|_| "no session")
    .expect("the session opened");
    let plan = Plan::checked(workload.name, 1_000_000, requests, 3, "none".into()).unwrap();
    let start_us = Pump::<LinkEnd<'_>>::now_us(&pump);
    let mut samples = Vec::new();
    open_loop(&mut client, &mut pump, &plan, SIM_WAIT_US, &mut samples);
    (start_us, plan, samples)
}

/// Over the simulated owner, 24 GETs intended at once queue behind the client's two request
/// slots: every GET yields one hit sample with its exact record, samples keep their intended
/// send, so a GET admitted late counts its wait, each sample ends one turn after the client's
/// own decision time, the end of the deciding turn, and the samples file holds the header the
/// judge's `HEADER_KEYS` names and one line per GET.
#[test]
fn an_open_loop_run_records_each_get_from_its_intended_send_over_the_simulated_owner() {
    let published: Vec<_> = (0..RECORDS.len()).map(|n| (n, record(n))).collect();
    let (start_us, plan, samples) = simulated_run(&published, &WORKLOADS[0], 24);
    assert_eq!(samples.len(), 24, "one sample per GET");
    for (i, sample) in samples.iter().enumerate() {
        assert_eq!(sample.intended_us, plan.intended_us(start_us, i as u64));
        assert_eq!(sample.record, plan.record(i as u64));
        assert_eq!(sample.stratum, Stratum::Hit, "GET {i}");
        assert!(
            sample.intended_us <= sample.attempted_us
                && sample.attempted_us <= sample.admitted_us
                && sample.admitted_us < sample.end_us
        );
        assert!(
            sample.attempted_us <= sample.intended_us + TURN_US,
            "GET {i} is first attempted on the pass after its intended send, whatever it waits for"
        );
        assert_eq!(
            sample.end_us,
            sample.decided_us + TURN_US,
            "GET {i} ends at the end of the turn whose poll decided it"
        );
    }
    let lagged = samples
        .iter()
        .filter(|sample| sample.admitted_us > sample.intended_us + TURN_US)
        .count();
    assert!(
        lagged > 0,
        "GETs beyond the two request slots wait, and their wait counts from the intended send"
    );
    let mut bytes = Vec::new();
    let digest = plan.write_samples(&mut bytes, &samples).unwrap();
    assert_eq!(
        digest,
        hex(&Sha256::digest(&bytes)),
        "the digest is the file's"
    );
    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 25);
    let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let mut keys: Vec<_> = header.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "previous",
            "rate",
            "records",
            "requests",
            "seed",
            "slots",
            "source",
            "started_unix_ms",
            "weights",
            "workload"
        ],
        "scripts/hit-gate.py HEADER_KEYS"
    );
    assert_eq!(header["workload"], "request-weighted");
    assert_eq!(header["slots"], SLOTS);
    assert_eq!(header["previous"], "none");
    let first: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(
        first,
        serde_json::json!([
            samples[0].intended_us,
            samples[0].attempted_us,
            samples[0].admitted_us,
            samples[0].end_us,
            samples[0].record,
            "hit",
            SOURCE
        ])
    );
}

/// A GET of a record the owner never published is a miss sample, never a hit.
#[test]
fn a_get_of_an_unpublished_record_is_a_miss_sample() {
    let published: Vec<_> = [0, 1, 3].into_iter().map(|n| (n, record(n))).collect();
    let (_, _, samples) = simulated_run(&published, &WORKLOADS[1], 4);
    assert_eq!(samples.len(), 4);
    assert!(
        samples
            .iter()
            .all(|sample| sample.record == 2 && sample.stratum == Stratum::Miss),
        "{samples:?}"
    );
}

/// CONTROL: an owner that publishes other bytes under record 2's key passes the client's own
/// checks, and the cell's comparison with the record it generates fails the run.
#[test]
#[should_panic(expected = "a hit's bytes are its record")]
fn control_a_hit_with_other_bytes_than_its_record_fails_the_cell() {
    let mut other = record(2);
    let last = other.len() - 1;
    other[last] ^= 1;
    simulated_run(&[(2, other)], &WORKLOADS[1], 2);
}
