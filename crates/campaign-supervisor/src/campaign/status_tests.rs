use crate::campaign::state_fixture::Sharded;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use super::status::{Lock, Member, failure_groups};
use super::{Error, name};
use crate::attempt::tests::{admit_request, artifact, stage, text};
use crate::record::{
    Admission, Artifact, Attempt, BOUND, Binding, BoundEvidence, Captured, Class, Digest,
    FindingKind, Finished, Intent, JobResult, Kernel, Pin, Started, Text,
};
use crate::step::{self, Outcome, Script, Step};
use crate::store::fixture::{Case, observed, replace, reread, scripted, snapshot};
use crate::store::{Dir, Store};

/// Whether `shown` lists one holder of the state directory's lock.
fn one_holder(shown: &Value) -> bool {
    shown["lock"]["holders"]
        .as_array()
        .is_some_and(|holders| holders.len() == 1)
}

/// The snapshot of the state directory at `path` as a JSON value.
pub(crate) fn status(path: &Path) -> Result<Value, Error> {
    super::status(path).map(|snapshot| {
        let mut bytes = Vec::new();
        snapshot
            .write(&mut bytes)
            .expect("a vector takes every write");
        serde_json::from_slice(&bytes).expect("a snapshot is one JSON object")
    })
}

fn admit(store: &Store, run: u64) -> Admission {
    admit_counts(store, run, &[])
}

fn admit_counts(store: &Store, run: u64, counts: &[(&str, u64)]) -> Admission {
    admit_request(
        store,
        &crate::campaign::Request {
            profile: text("upload"),
            campaign: text("c1"),
            run,
            attempts: 3,
            counts: counts
                .iter()
                .map(|(key, value)| (text(key), *value))
                .collect(),
        },
    )
    .unwrap()
    .record
}

fn open(store: &Store, parent: &Dir, entry: &str) -> Dir {
    if let Some(directory) = store.open_dir(parent, &name(entry)).unwrap() {
        return directory;
    }
    store.mkdir(parent, &name(entry)).unwrap();
    store.open_dir(parent, &name(entry)).unwrap().unwrap()
}

/// The `jobs/` shard of the job id or entry name `entry`.
fn jobs(store: &Store, entry: impl AsRef<str>) -> Dir {
    crate::layout::make_shard(store, crate::layout::JOBS, entry.as_ref()).unwrap()
}

/// Job `id`'s attempt history directory.
fn history(store: &Store, id: impl AsRef<str>) -> Dir {
    let id = id.as_ref();
    let shard = crate::layout::make_shard(store, crate::layout::ATTEMPTS, id).unwrap();
    open(store, &shard, id)
}

fn attempt_id(job: &Admission, number: u64) -> String {
    format!("{}-{number:04}", job.job().id())
}

fn attempt_record(job: &Admission, number: u64) -> Attempt {
    Attempt {
        attempt: text(&attempt_id(job, number)),
        file_bytes: BOUND,
        job: job.job().id().digest(),
        manifest: job.job().manifest_sha256(),
        number,
    }
}

fn intent(id: &str) -> Intent {
    Intent {
        attempt: text(id),
        boot: text("boot"),
        cgroup: text("/sys/fs/cgroup/campaign/attempt"),
    }
}

fn started(id: &str) -> Started {
    Started {
        attempt: text(id),
        baseline: Kernel::default(),
        boot: text("boot"),
        cgroup: text("/sys/fs/cgroup/campaign/attempt"),
        cgroup_inode: 7,
        launcher_pid: 11,
    }
}

fn launched(store: &Store, job: &Admission, number: u64) -> (Dir, String) {
    let history = history(store, job.job().id().to_string());
    let directory = open(store, &history, &format!("{number:04}"));
    let id = attempt_id(job, number);
    store
        .create_record(&directory, &name("attempt"), &attempt_record(job, number))
        .unwrap();
    store
        .create_record(&directory, &name("intent"), &intent(&id))
        .unwrap();
    store
        .create_record(&directory, &name("started"), &started(&id))
        .unwrap();
    (directory, id)
}

fn finished(id: &str, bound: Option<BoundEvidence>) -> Finished {
    Finished {
        attempt: text(id),
        binding: if bound.is_some() {
            Binding::Matching
        } else {
            Binding::Missing
        },
        bound,
        class: Class::Pass,
        exit: Some(0),
        interruption: None,
        kernel: Kernel {
            cpu: [("usage_usec", 4_000_000), ("throttled_usec", 300)]
                .into_iter()
                .map(|(key, value)| (text(key), value))
                .collect(),
            memory: [(text("oom"), 2)].into(),
            pids: [(text("max"), 5)].into(),
        },
        residual_members: false,
        signal: None,
        watchdog: false,
    }
}

fn bound(
    store: &Store,
    directory: &Dir,
    job: &Admission,
    number: u64,
    edit: impl FnOnce(&mut Artifact),
) -> BoundEvidence {
    let id = attempt_id(job, number);
    let mut artifact = artifact(&id, job.job().manifest_sha256());
    edit(&mut artifact);
    let staged = stage(store, directory, &attempt_record(job, number), &artifact);
    let stored = store
        .read_record::<Artifact>(&staged, &name("artifact"))
        .unwrap()
        .unwrap();
    BoundEvidence {
        artifact: Digest::of(stored.read().bytes()),
        attempt: text(&id),
        bundle: artifact.bundle,
    }
}

fn finish(store: &Store, directory: &Dir, finished: &Finished) {
    if let Some(bound) = &finished.bound {
        store
            .create_record(directory, &name("bound"), bound)
            .unwrap();
    }
    store
        .create_record(directory, &name("finished"), finished)
        .unwrap();
}

fn result(job: &Admission, attempt: u64, finished: Finished) -> JobResult {
    JobResult {
        attempt,
        finished,
        job: job.job().id().digest(),
        manifest: job.job().manifest_sha256(),
    }
}

fn settle(store: &Store, job: &Admission, suffix: &str, record: &impl crate::record::Record) {
    store
        .create_record(
            &jobs(store, job.job().id().to_string()),
            &name(&format!("{}{suffix}", job.job().id())),
            record,
        )
        .unwrap();
}

fn row<'a>(shown: &'a Value, job: &Admission) -> &'a Value {
    shown["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == job.job().id().to_string())
        .unwrap()
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn set_mtime(path: &Path, ms: i64) {
    let offset = Duration::from_millis(ms.unsigned_abs());
    let time = if ms < 0 {
        UNIX_EPOCH - offset
    } else {
        UNIX_EPOCH + offset
    };
    fs::File::open(path).unwrap().set_modified(time).unwrap();
}

fn mkdir(path: &Path) {
    fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(path)
        .unwrap();
}

#[test]
fn status_reports_every_job_state_and_attempt_fact_under_the_controller_lock() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let queued = admit(&store, 0);
    let running = admit(&store, 1);
    let waiting = admit(&store, 2);
    let settled = admit(&store, 3);
    let settling = admit(&store, 4);
    let retried = admit(&store, 5);
    let other = admit_counts(&store, 6, &[("records", 80)]);
    launched(&store, &running, 1);
    let (directory, id) = launched(&store, &waiting, 1);
    finish(&store, &directory, &finished(&id, None));
    let (directory, id) = launched(&store, &settled, 1);
    let evidence = bound(&store, &directory, &settled, 1, |artifact| {
        artifact.reason = text("counts reached");
        let summary = artifact.summary.as_mut().unwrap();
        summary.cause = Some(text("violation, violating Progress"));
        summary.identity = Some(text("02aa"));
        summary.ledger = Some(text("credited"));
        summary.unsuccessful = Some(text("old read held"));
        summary.first_failure = Some(crate::record::Event {
            node: None,
            operation: None,
            record: text("00"),
            semantic_record: 4,
            virtual_us: Some(600),
        });
    });
    let done = finished(&id, Some(evidence));
    finish(&store, &directory, &done);
    let marker = store
        .read_record::<Finished>(&directory, &name("finished"))
        .unwrap()
        .unwrap();
    store
        .create_record(
            &directory,
            &name("captured"),
            &Captured {
                attempt: text(&id),
                finding: None,
                finished: Digest::of(marker.read().bytes()),
            },
        )
        .unwrap();
    drop(marker);
    settle(
        &store,
        &settled,
        JobResult::SUFFIX,
        &result(&settled, 1, done),
    );
    let (directory, id) = launched(&store, &settling, 1);
    let mut failed = finished(&id, None);
    failed.class = Class::Violation;
    finish(&store, &directory, &failed);
    settle(
        &store,
        &settling,
        Pin::SUFFIX,
        &Pin {
            result: result(&settling, 1, failed),
        },
    );
    let (directory, id) = launched(&store, &retried, 1);
    finish(&store, &directory, &finished(&id, None));
    launched(&store, &retried, 2);
    let probes = open(&store, store.root(), "probes");
    open(&store, &probes, "probe-1");
    open(&store, &probes, "probe-2");
    store
        .create_once(&probes, &name("stray"), b"not a probe")
        .unwrap();

    let history = |job: &Admission| {
        case.state
            .join(crate::campaign::state_fixture::attempts_dir(
                job.job().id().to_string(),
            ))
    };
    let records = history(&settled).join("0001");
    set_mtime(&records.join("intent"), 1_700_000_000_123);
    set_mtime(&records.join("started"), 1_700_000_001_456);
    set_mtime(&records.join("finished"), 1_700_000_060_789);
    let early = history(&running).join("0001");
    set_mtime(&early.join("started"), -5_000);

    let before = snapshot(&case.state);
    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let shown = reread(
        || {
            step::install(Some(Script {
                free_space: Some((7_000, 9)),
                ..Script::default()
            }));
            let shown = status(&case.state);
            step::install(None);
            shown.unwrap()
        },
        one_holder,
    );
    let end = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    assert_eq!(snapshot(&case.state), before);
    assert!(matches!(
        Store::open(&case.state),
        Err(crate::store::Error::Busy)
    ));

    assert_eq!(
        keys(&shown),
        [
            "config",
            "failure_groups",
            "findings",
            "format",
            "held_probes",
            "jobs",
            "lock",
            "observed_ms",
            "probes",
            "release_blockers",
            "space",
            "state",
            "variants",
        ]
        .into()
    );
    assert_eq!(shown["format"], 1);
    let holders = shown["lock"]["holders"].as_array().unwrap();
    assert_eq!(holders.len(), 1, "the controller lock alone: {holders:?}");
    assert_eq!(keys(&holders[0]), ["command", "mode", "pid"].into());
    assert_eq!(holders[0]["mode"], "exclusive");
    assert_eq!(holders[0]["pid"], std::process::id());
    drop(store);
    let released = status(&case.state).unwrap();
    assert_eq!(released["lock"], json!({"holders": []}));
    let observed = shown["observed_ms"].as_u64().unwrap();
    assert!(start.as_millis() as u64 <= observed && observed <= end.as_millis() as u64);
    assert_eq!(
        shown["state"],
        fs::canonicalize(&case.state).unwrap().display().to_string()
    );
    assert!(shown["config"].is_null());
    assert_eq!(
        shown["space"],
        json!({"free_bytes": 7_000, "free_inodes": 9})
    );
    assert_eq!(shown["probes"], 2);
    assert_eq!(shown["held_probes"][0]["entry"], "stray");
    assert_eq!(shown["held_probes"][0]["held_code"], "unreadable");
    assert_eq!(shown["jobs"].as_array().unwrap().len(), 7);

    assert_eq!(row(&shown, &queued)["state"], "queued");
    assert_eq!(row(&shown, &running)["state"], "running");
    assert_eq!(row(&shown, &waiting)["state"], "waiting");
    assert_eq!(row(&shown, &retried)["state"], "running");
    assert_eq!(row(&shown, &retried)["attempts"][1]["number"], 2);
    let pinned = row(&shown, &settling);
    assert_eq!(pinned["state"], "settling");
    assert!(pinned["result"].is_null());
    assert_eq!(pinned["pin"]["class"], "violation");

    let done = row(&shown, &settled);
    assert_eq!(
        keys(done),
        [
            "attempts",
            "attempts_allowed",
            "attempts_held",
            "build",
            "campaign",
            "class",
            "executable",
            "id",
            "pin",
            "profile",
            "purpose",
            "result",
            "run",
            "seed",
            "state",
            "variant",
        ]
        .into()
    );
    assert_eq!(done["state"], "settled");
    assert_eq!(done["profile"], "upload");
    assert_eq!(done["campaign"], "c1");
    assert_eq!(done["run"], 3);
    assert_eq!(done["seed"], settled.job().seed());
    assert_eq!(done["class"], json!(settled.job().experiment().class));
    assert_eq!(done["purpose"], "campaign");
    assert_eq!(done["attempts_allowed"], 3);
    assert_eq!(done["build"], "b".repeat(64));
    assert_eq!(done["executable"], "e".repeat(64));
    assert!(done["pin"].is_null());
    assert!(done["attempts_held"].is_null());
    assert_eq!(
        done["result"],
        json!({"attempt": 1, "class": "pass", "exit": 0, "signal": null, "watchdog": false})
    );

    let attempt = &done["attempts"][0];
    assert_eq!(
        keys(attempt),
        [
            "attempt",
            "captured",
            "finding",
            "finished",
            "finished_ms",
            "intent_ms",
            "number",
            "sim",
            "started_ms",
        ]
        .into()
    );
    assert_eq!(attempt["number"], 1);
    assert_eq!(attempt["attempt"], attempt_id(&settled, 1));
    assert_eq!(attempt["intent_ms"], 1_700_000_000_123u64);
    assert_eq!(attempt["started_ms"], 1_700_000_001_456u64);
    assert_eq!(attempt["finished_ms"], 1_700_000_060_789u64);
    assert_eq!(attempt["captured"], true);
    assert!(attempt["finding"].is_null());
    assert_eq!(
        attempt["finished"],
        json!({
            "class": "pass", "exit": 0, "signal": null, "watchdog": false,
            "interruption": null, "binding": "matching", "residual_members": false,
            "kernel": {
                "cpu_usage_usec": 4_000_000, "cpu_throttled_usec": 300,
                "cpu_nr_throttled": null, "memory": {"oom": 2}, "pids": {"max": 5},
            },
        })
    );
    assert_eq!(
        attempt["sim"],
        json!({
            "class": "counts", "command": "run", "reason": "counts reached",
            "terminal": "complete pass fired=03 required=03",
            "cause": "violation, violating Progress", "identity": "02aa",
            "digest": Digest::of(b"semantic"), "decisions": 1, "ledger": "credited",
            "failure_virtual_us": 600, "unsuccessful": "old read held",
        })
    );
    let open = &row(&shown, &running)["attempts"][0];
    assert!(open["intent_ms"].is_u64());
    assert!(open["started_ms"].is_null());
    assert!(open["finished_ms"].is_null());
    assert!(open["sim"].is_null());
    assert_eq!(open["captured"], false);

    let variant = done["variant"].as_str().unwrap();
    let counts = serde_json::to_vec(&settled.job().experiment().counts).unwrap();
    assert_eq!(variant, &Digest::of(&counts).to_string()[..16]);
    assert_eq!(row(&shown, &queued)["variant"], variant);
    let distinct = row(&shown, &other)["variant"].as_str().unwrap();
    assert_ne!(distinct, variant);
    assert_eq!(shown["variants"].as_object().unwrap().len(), 2);
    assert_eq!(
        shown["variants"][variant],
        json!(settled.job().experiment().counts)
    );
    assert_eq!(
        shown["variants"][distinct],
        json!(other.job().experiment().counts)
    );
}

#[test]
fn status_orders_attempts_by_number_past_four_digits() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = admit_request(
        &store,
        &crate::campaign::Request {
            profile: text("upload"),
            campaign: text("c1"),
            run: 0,
            attempts: 10_000,
            counts: Default::default(),
        },
    )
    .unwrap()
    .record;
    let (directory, id) = launched(&store, &job, 9_999);
    finish(&store, &directory, &finished(&id, None));
    launched(&store, &job, 10_000);
    let history = case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(
            job.job().id().to_string(),
        ));
    for number in 1..9_999 {
        mkdir(&history.join(format!("{number:04}")));
    }
    drop(store);
    let shown = status(&case.state).unwrap();
    let row = row(&shown, &job);
    assert_eq!(row["state"], "running");
    assert_eq!(row["attempts"][9_998]["number"], 9_999);
    assert_eq!(row["attempts"][9_999]["number"], 10_000);
}

#[test]
fn status_holds_settlement_records_that_fail_the_read_or_binding_rule() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let mut cases = Vec::new();
    let corrupt = admit(&store, 0);
    store
        .create_once(
            &jobs(&store, corrupt.job().id().to_string()),
            &name(&format!("{}{}", corrupt.job().id(), JobResult::SUFFIX)),
            b"corrupt",
        )
        .unwrap();
    launched(&store, &corrupt, 1);
    cases.push((corrupt, "result", "malformed", "held"));
    type Edit = fn(&Admission, &mut JobResult);
    let edits: [(u64, Edit); 5] = [
        (1, |_, result| result.job = Digest::of(b"other job")),
        (2, |job, result| {
            result.attempt = 0;
            result.finished.attempt = text(&attempt_id(job, 0));
        }),
        (3, |job, result| {
            result.attempt = 4;
            result.finished.attempt = text(&attempt_id(job, 4));
        }),
        (4, |job, result| {
            result.finished.attempt = text(&attempt_id(job, 2))
        }),
        (5, |job, result| {
            result.finished.bound = Some(BoundEvidence {
                artifact: Digest::of(b"artifact"),
                attempt: text(&attempt_id(job, 2)),
                bundle: None,
            })
        }),
    ];
    for (run, edit) in edits {
        let job = admit(&store, run);
        launched(&store, &job, 1);
        let mut record = result(&job, 1, finished(&attempt_id(&job, 1), None));
        edit(&job, &mut record);
        settle(&store, &job, JobResult::SUFFIX, &record);
        cases.push((job, "result", "binding", "held"));
    }
    let pinned = admit(&store, 6);
    launched(&store, &pinned, 1);
    let mut pin = Pin {
        result: result(&pinned, 1, finished(&attempt_id(&pinned, 1), None)),
    };
    pin.result.manifest = Digest::of(b"other manifest");
    settle(&store, &pinned, Pin::SUFFIX, &pin);
    cases.push((pinned, "pin", "binding", "held"));
    let resolved = admit(&store, 7);
    let (directory, id) = launched(&store, &resolved, 1);
    finish(&store, &directory, &finished(&id, None));
    let good = result(&resolved, 1, finished(&attempt_id(&resolved, 1), None));
    settle(&store, &resolved, JobResult::SUFFIX, &good);
    let mut pin = Pin { result: good };
    pin.result.attempt = 2;
    settle(&store, &resolved, Pin::SUFFIX, &pin);
    cases.push((resolved, "pin", "binding", "settled"));
    drop(store);

    let shown = status(&case.state).unwrap();
    for (job, field, code, state) in &cases {
        let row = row(&shown, job);
        assert_eq!(row[*field]["held_code"], *code, "{row}");
        assert!(row[*field]["held"].is_string());
        assert_eq!(row["state"], *state, "{row}");
    }
    assert_eq!(
        row(&shown, &cases[1].0)["result"]["held"],
        "settlement binding differs"
    );
}

#[test]
fn status_holds_bound_artifacts_that_differ_from_the_finish_evidence() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let digest = admit(&store, 0);
    let (directory, id) = launched(&store, &digest, 1);
    let mut evidence = bound(&store, &directory, &digest, 1, |_| {});
    evidence.artifact = Digest::of(b"other");
    finish(&store, &directory, &finished(&id, Some(evidence)));
    let run = admit(&store, 1);
    let (directory, id) = launched(&store, &run, 1);
    let evidence = bound(&store, &directory, &run, 1, |artifact| {
        artifact.run_id = text("another-run");
    });
    finish(&store, &directory, &finished(&id, Some(evidence)));
    let bundle = admit(&store, 2);
    let (directory, id) = launched(&store, &bundle, 1);
    let mut evidence = bound(&store, &directory, &bundle, 1, |_| {});
    evidence.bundle = Some(Digest::of(b"other bundle"));
    finish(&store, &directory, &finished(&id, Some(evidence)));
    let missing = admit(&store, 3);
    let (directory, id) = launched(&store, &missing, 1);
    let evidence = BoundEvidence {
        artifact: Digest::of(b"artifact"),
        attempt: text(&id),
        bundle: None,
    };
    finish(&store, &directory, &finished(&id, Some(evidence)));
    type Edit = fn(&mut Artifact);
    let edits: [(u64, Edit); 3] = [
        (4, |artifact| {
            artifact.manifest = Some(Digest::of(b"other manifest"))
        }),
        (5, |artifact| artifact.command = text("replay")),
        (6, |artifact| {
            artifact.archive = Some(Digest::of(b"other build"))
        }),
    ];
    let mut misbound = Vec::new();
    for (run, edit) in edits {
        let job = admit(&store, run);
        let (directory, id) = launched(&store, &job, 1);
        let evidence = bound(&store, &directory, &job, 1, edit);
        finish(&store, &directory, &finished(&id, Some(evidence)));
        misbound.push(job);
    }
    let label = admit(&store, 7);
    let (directory, id) = launched(&store, &label, 1);
    let evidence = bound(&store, &directory, &label, 1, |_| {});
    let mut labelled = finished(&id, Some(evidence));
    labelled.binding = Binding::Misbound;
    finish(&store, &directory, &labelled);
    let stored = admit(&store, 8);
    let (directory, id) = launched(&store, &stored, 1);
    let evidence = bound(&store, &directory, &stored, 1, |_| {});
    let mut other = evidence.clone();
    other.bundle = Some(Digest::of(b"other bundle"));
    store
        .create_record(&directory, &name("bound"), &other)
        .unwrap();
    store
        .create_record(
            &directory,
            &name("finished"),
            &finished(&id, Some(evidence)),
        )
        .unwrap();
    let unrecorded = admit(&store, 9);
    let (directory, id) = launched(&store, &unrecorded, 1);
    let evidence = bound(&store, &directory, &unrecorded, 1, |_| {});
    store
        .create_record(
            &directory,
            &name("finished"),
            &finished(&id, Some(evidence)),
        )
        .unwrap();
    let absent = admit(&store, 10);
    let (directory, id) = launched(&store, &absent, 1);
    let evidence = bound(&store, &directory, &absent, 1, |_| {});
    finish(&store, &directory, &finished(&id, Some(evidence)));
    let unwritten = admit(&store, 11);
    let (directory, id) = launched(&store, &unwritten, 1);
    let evidence = bound(&store, &directory, &unwritten, 1, |_| {});
    finish(&store, &directory, &finished(&id, Some(evidence)));
    let unbound = admit(&store, 12);
    let (directory, id) = launched(&store, &unbound, 1);
    let mut matching = finished(&id, None);
    matching.binding = Binding::Matching;
    finish(&store, &directory, &matching);
    drop(store);
    let history = |job: &Admission| {
        case.state
            .join(crate::campaign::state_fixture::attempts_dir(
                job.job().id().to_string(),
            ))
            .join("0001")
            .join("artifacts")
            .join(attempt_id(job, 1))
    };
    fs::remove_dir_all(history(&absent)).unwrap();
    fs::remove_file(history(&unwritten).join("artifact")).unwrap();

    let shown = status(&case.state).unwrap();
    for (job, reason) in [
        (&digest, "artifact differs from the bound digest"),
        (&run, "bound artifact binding differs"),
        (&bundle, "bound artifact binding differs"),
        (&missing, "bound artifacts missing"),
        (&misbound[0], "bound artifact binding differs"),
        (&misbound[1], "bound artifact binding differs"),
        (&misbound[2], "bound artifact binding differs"),
        (&label, "bound evidence under another binding"),
        (&stored, "stored binding differs"),
        (&unrecorded, "finished lacks bound record"),
        (&absent, "bound artifact missing"),
        (&unwritten, "bound artifact record missing"),
        (&unbound, "matching binding without bound evidence"),
    ] {
        let row = row(&shown, job);
        let sim = &row["attempts"][0]["sim"];
        assert_eq!(sim["held"], reason, "{row}");
        assert_eq!(sim["held_code"], "binding");
        assert!(sim.get("class").is_none());
        assert_eq!(row["attempts"][0]["finished"]["class"], "pass");
        assert_eq!(row["state"], "waiting");
    }
}

#[test]
fn status_reports_a_record_failing_the_read_rule_as_a_held_attempt_row() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = admit(&store, 0);
    let other = admit(&store, 1);
    let (directory, _) = launched(&store, &job, 1);
    store
        .create_once(&directory, &name("finished"), b"corrupt")
        .unwrap();
    drop(store);
    let shown = status(&case.state).unwrap();
    let held_row = row(&shown, &job);
    let held = &held_row["attempts"][0];
    assert_eq!(held["entry"], "0001");
    assert!(held["held"].is_string());
    assert_eq!(held["held_code"], "malformed");
    assert!(held.get("number").is_none());
    assert_eq!(held_row["state"], "held");
    assert_eq!(row(&shown, &other)["state"], "queued");
}

#[test]
fn status_holds_each_attempt_record_that_names_another_attempt_or_differs() {
    for (wrong, reason) in [
        ("attempt", "attempt record names another attempt"),
        ("intent", "attempt record names another attempt"),
        ("started", "attempt record names another attempt"),
        ("finished", "attempt record names another attempt"),
        ("bound", "attempt record names another attempt"),
        ("captured", "attempt record names another attempt"),
        ("number", "attempt record binding differs"),
        ("job", "attempt record binding differs"),
        ("manifest", "attempt record binding differs"),
        ("boot", "started record differs from its intent"),
        ("cgroup", "started record differs from its intent"),
        ("marker", "capture marker differs from the finish"),
        ("finding", "capture marker differs from the finish"),
        ("unfinished", "capture marker without a finish"),
    ] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let job = admit(&store, 0);
        let history = history(&store, job.job().id().to_string());
        let directory = open(&store, &history, "0001");
        let id = attempt_id(&job, 1);
        let other = attempt_id(&job, 2);
        let named = |record: &str| text(if record == wrong { &other } else { &id });
        let mut attempt = attempt_record(&job, 1);
        attempt.attempt = named("attempt");
        if wrong == "number" {
            attempt.number = 2;
        }
        if wrong == "job" {
            attempt.job = Digest::of(b"other job");
        }
        if wrong == "manifest" {
            attempt.manifest = Digest::of(b"other manifest");
        }
        store
            .create_record(&directory, &name("attempt"), &attempt)
            .unwrap();
        let mut intent = intent(&id);
        intent.attempt = named("intent");
        store
            .create_record(&directory, &name("intent"), &intent)
            .unwrap();
        let mut started = started(&id);
        started.attempt = named("started");
        if wrong == "cgroup" {
            started.cgroup = text("/sys/fs/cgroup/campaign/other");
        }
        if wrong == "boot" {
            started.boot = text("another boot");
        }
        store
            .create_record(&directory, &name("started"), &started)
            .unwrap();
        let mut finish_record = finished(&id, None);
        finish_record.attempt = named("finished");
        if wrong == "bound" {
            finish_record.bound = Some(BoundEvidence {
                artifact: Digest::of(b"artifact"),
                attempt: text(&other),
                bundle: None,
            });
        }
        let mut digest = Digest::of(b"unwritten finish");
        if wrong != "unfinished" {
            finish(&store, &directory, &finish_record);
            let read = store
                .read_record::<Finished>(&directory, &name("finished"))
                .unwrap()
                .unwrap();
            if wrong != "marker" {
                digest = Digest::of(read.read().bytes());
            }
        }
        store
            .create_record(
                &directory,
                &name("captured"),
                &Captured {
                    attempt: named("captured"),
                    finding: (wrong == "finding").then(|| text(&other)),
                    finished: digest,
                },
            )
            .unwrap();
        drop(store);
        let shown = status(&case.state).unwrap();
        let row = row(&shown, &job);
        let held = &row["attempts"][0];
        assert_eq!(held["entry"], "0001", "{wrong}");
        assert_eq!(held["held"], reason, "{wrong}");
        assert_eq!(held["held_code"], "binding", "{wrong}");
        assert_eq!(row["state"], "held", "{wrong}");
    }
}

#[test]
fn status_holds_misnamed_and_out_of_limit_attempt_entries_and_history_gaps() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = admit(&store, 0);
    let (directory, id) = launched(&store, &job, 1);
    finish(&store, &directory, &finished(&id, None));
    let history = case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(
            job.job().id().to_string(),
        ));
    for entry in ["0000", "1", "abc", "0004"] {
        mkdir(&history.join(entry));
    }
    let stray = admit(&store, 1);
    let (directory, id) = launched(&store, &stray, 1);
    finish(&store, &directory, &finished(&id, None));
    mkdir(
        &case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                stray.job().id().to_string(),
            ))
            .join("0001.bak"),
    );
    let file = admit(&store, 2);
    let healthy = admit(&store, 3);
    store
        .create_once(
            &crate::layout::make_shard(
                &store,
                crate::layout::ATTEMPTS,
                &file.job().id().to_string(),
            )
            .unwrap(),
            &name(&file.job().id().to_string()),
            b"file",
        )
        .unwrap();
    drop(store);

    let shown = status(&case.state).unwrap();
    let job_row = row(&shown, &job);
    assert_eq!(job_row["attempts"][0]["number"], 1);
    let held: Vec<_> = job_row["attempts"].as_array().unwrap()[1..]
        .iter()
        .map(|row| {
            assert_eq!(row["held_code"], "binding");
            assert!(row.get("number").is_none());
            (
                row["entry"].as_str().unwrap(),
                row["held"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        held,
        [
            ("0004", "attempt number outside the frozen limit"),
            ("0000", "noncanonical attempt name"),
            ("1", "noncanonical attempt name"),
            ("abc", "invalid attempt name"),
        ]
    );
    assert_eq!(
        job_row["attempts_held"]["held"],
        "attempt history has gaps or duplicates"
    );
    assert_eq!(job_row["state"], "held");
    let stray_row = row(&shown, &stray);
    assert_eq!(stray_row["attempts"][1]["entry"], "0001.bak");
    assert_eq!(stray_row["state"], "held");
    let file_row = row(&shown, &file);
    assert!(file_row["attempts"].as_array().unwrap().is_empty());
    assert!(file_row["attempts_held"]["held"].is_string());
    assert_eq!(file_row["state"], "held");
    assert_eq!(row(&shown, &healthy)["state"], "queued");
}

#[test]
fn status_holds_job_entries_dispatch_refuses() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = admit(&store, 0);
    let jobs = |entry: &str| jobs(&store, entry);
    let orphan = "c".repeat(64);
    let unadmitted = "d".repeat(64);
    store
        .create_once(
            &jobs(format!("{orphan}{}", Pin::SUFFIX).as_ref()),
            &name(&format!("{orphan}{}", Pin::SUFFIX)),
            b"{}",
        )
        .unwrap();
    store
        .create_once(&jobs("abstray.txt"), &name("abstray.txt"), b"")
        .unwrap();
    store
        .create_once(&jobs("abfoo.json"), &name("abfoo.json"), b"{}")
        .unwrap();
    let bare = admit(&store, 1);
    let bare_id = bare.job().id().to_string();
    store
        .create_once(&jobs(bare_id.as_ref()), &name(&bare_id), b"")
        .unwrap();
    let shadow = "e".repeat(64);
    store
        .create_once(&jobs(shadow.as_ref()), &name(&shadow), b"")
        .unwrap();
    let corrupt = "a".repeat(64);
    store
        .create_once(
            &jobs(format!("{corrupt}.json").as_ref()),
            &name(&format!("{corrupt}.json")),
            b"corrupt",
        )
        .unwrap();
    store
        .create_once(
            &jobs(format!("{corrupt}.manifest").as_ref()),
            &name(&format!("{corrupt}.manifest")),
            b"manifest",
        )
        .unwrap();
    let manifest_only = "b".repeat(64);
    store
        .create_once(
            &jobs(&manifest_only),
            &name(&format!("{manifest_only}.manifest")),
            b"manifest",
        )
        .unwrap();
    history(&store, &unadmitted);
    history(&store, &shadow);
    history(&store, &orphan);
    drop(store);

    let shown = status(&case.state).unwrap();
    let held: BTreeSet<_> = shown["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row.get("held").is_some())
        .map(|row| {
            let reason = row["held"].as_str().unwrap();
            (
                row["id"].as_str().unwrap(),
                if row["held_code"] == "malformed" {
                    ""
                } else {
                    reason
                },
                row["held_code"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        held,
        [
            (corrupt.as_str(), "", "malformed"),
            (
                manifest_only.as_str(),
                "job dependency without job record",
                "binding"
            ),
            (bare_id.as_str(), "unknown job entry", "binding"),
            (orphan.as_str(), "settlement without job record", "binding"),
            (
                unadmitted.as_str(),
                "attempt history without job record",
                "binding"
            ),
            (shadow.as_str(), "unknown job entry", "binding"),
            (
                shadow.as_str(),
                "attempt history without job record",
                "binding"
            ),
            ("abfoo", "invalid job identity filename", "identity"),
            ("abstray.txt", "unknown job entry", "binding"),
        ]
        .into()
    );
    assert_eq!(shown["jobs"].as_array().unwrap().len(), 11);
    let ids: Vec<_> = shown["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert!(ids.is_sorted(), "{ids:?}");
    assert_eq!(row(&shown, &job)["state"], "queued");
    assert_eq!(row(&shown, &bare)["state"], "queued");
}

#[test]
fn status_verifies_each_queued_admission_once() {
    let case = Case::new();
    let reads = |trace: Vec<Step>| trace.iter().filter(|step| **step == Step::Read).count();
    let mut counts = Vec::new();
    let mut last = None;
    for run in 0..3 {
        let store = Store::open(&case.state).unwrap();
        last = Some(admit(&store, run));
        drop(store);
        let (shown, trace) = scripted([], || status(&case.state));
        shown.unwrap().unwrap();
        counts.push(reads(trace));
    }
    let view = crate::store::View::unfenced(&case.state).unwrap();
    let id = last.unwrap().job().id().to_string();
    let jobs = view.shard_jobs(&id).unwrap().unwrap();
    let (verified, trace) = scripted([], || super::show::verified_job(&view, &jobs, &id));
    verified.unwrap().unwrap();
    let admission = reads(trace);
    assert_eq!(admission, 2);
    assert_eq!(counts[1] - counts[0], admission);
    assert_eq!(counts[2] - counts[1], admission);
}

#[test]
fn status_lists_a_held_admission_as_a_blocker_only_under_a_digest_name() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let corrupt = "a".repeat(64);
    for (entry, bytes) in [
        (format!("{corrupt}.json"), &b"corrupt"[..]),
        (format!("{corrupt}.manifest"), b"manifest"),
        ("abfoo.json".to_owned(), b"{}"),
    ] {
        store
            .create_once(&jobs(&store, &entry), &name(&entry), bytes)
            .unwrap();
    }
    drop(store);
    let shown = status(&case.state).unwrap();
    let blocker = crate::layout::job_file(&corrupt, &format!("{corrupt}.json"))
        .display()
        .to_string();
    let rows: Vec<_> = shown["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["id"].as_str().unwrap(),
                row["held_code"].as_str().unwrap(),
                row["blocker"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(rows, [(blocker.as_str(), "malformed", true)]);
    assert_eq!(shown["release_blockers"], json!([blocker]));
}

#[test]
fn status_refuses_an_unmarked_state_directory_without_effects() {
    let case = Case::new();
    drop(Store::open(&case.state).unwrap());
    fs::remove_file(case.state.join(".state")).unwrap();
    let before = snapshot(&case.state);
    assert!(matches!(
        status(&case.state),
        Err(Error::Store(crate::store::Error::Refused(
            crate::store::Refusal::Unmarked
        )))
    ));
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn status_rejects_a_state_path_that_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt;
    let case = Case::new();
    let state = case.root.join(std::ffi::OsStr::from_bytes(b"state-\xff"));
    mkdir(&state);
    drop(Store::open(&state).unwrap());
    let before = snapshot(&state);
    let error = status(&state).expect_err("a lossy state path is rejected");
    assert!(
        matches!(&error, Error::Rejected(why) if why == "the state path must be UTF-8"),
        "{error}"
    );
    assert_eq!(snapshot(&state), before);
}

#[test]
fn status_refuses_a_state_directory_replaced_during_the_read() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    admit(&store, 0);
    drop(store);
    let before = snapshot(&case.state);
    let state = case.state.clone();
    let old = case.root.join("old-state");
    let replaced = old.clone();
    let mut reached = false;
    let result = observed(
        move |at| {
            if at == Step::List && !reached {
                reached = true;
                replace(&state, &replaced);
            }
        },
        || status(&case.state),
    );
    assert!(
        matches!(&result, Err(Error::Held(reason)) if reason == "state directory moved during status"),
        "{result:?}"
    );
    assert_eq!(snapshot(&old), before);
    assert!(snapshot(&case.state).is_empty());
}

/// The lock holder read after the job pass is part of the snapshot's read,
/// so a state directory replaced while it runs is refused like one replaced
/// during the job pass.
#[test]
fn status_refuses_a_state_directory_replaced_during_the_late_holder_read() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    admit(&store, 0);
    drop(store);
    let (clean, reached) = scripted([], || status(&case.state));
    assert_eq!(clean.unwrap().unwrap()["lock"], json!({"holders": []}));
    let late_open = reached.iter().rposition(|at| *at == Step::Open).unwrap();
    let state = case.state.clone();
    let replaced = case.root.join("old-state");
    let mut index = 0;
    let result = observed(
        move |_| {
            if index == late_open {
                replace(&state, &replaced);
            }
            index += 1;
        },
        || status(&case.state),
    );
    assert!(
        matches!(&result, Err(Error::Held(reason)) if reason == "state directory moved during status"),
        "{result:?}"
    );
}

#[test]
fn status_ends_with_a_host_fault_at_every_step_without_effects() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store
        .create_once(store.root(), &name("config.json"), b"corrupt")
        .unwrap();
    let job = admit(&store, 0);
    let (directory, id) = launched(&store, &job, 1);
    let evidence = bound(&store, &directory, &job, 1, |_| {});
    let done = finished(&id, Some(evidence));
    finish(&store, &directory, &done);
    settle(&store, &job, JobResult::SUFFIX, &result(&job, 1, done));
    let probes = open(&store, store.root(), "probes");
    open(&store, &probes, "probe-1");
    history(&store, "d".repeat(64));
    drop(store);
    let before = snapshot(&case.state);
    let (clean, reached) = scripted([], || status(&case.state));
    assert_eq!(clean.unwrap().unwrap()["jobs"][0]["state"], "settled");
    for (index, at) in reached.iter().enumerate() {
        let (result, _) = scripted([(index, Outcome::Errno(libc::EIO))], || status(&case.state));
        let error = result.unwrap().expect_err("a host fault ends the snapshot");
        assert!(error.host_fault(), "{index} {at:?}: {error}");
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
fn status_names_a_report_snapshot_as_a_shared_holder() {
    let case = Case::new();
    drop(Store::open(&case.state).unwrap());
    let report = crate::store::View::snapshot(&case.state).unwrap();
    let shown = reread(|| status(&case.state).unwrap(), one_holder);
    let holders = shown["lock"]["holders"].as_array().unwrap();
    assert_eq!(holders.len(), 1, "{holders:?}");
    assert_eq!(holders[0]["mode"], "shared");
    assert_eq!(holders[0]["pid"], std::process::id());
    drop(report);
    assert_eq!(status(&case.state).unwrap()["lock"], json!({"holders": []}));
}

#[test]
fn an_unknown_lock_serializes_as_its_reason_alone() {
    let unknown = Lock::of(Err("/proc/locks is absent".into()));
    assert_eq!(
        serde_json::to_value(unknown).unwrap(),
        json!({"unknown": "/proc/locks is absent"})
    );
}

/// A controller that holds the lock at either holder read is reported: one
/// taken during the job pass is found by the read after it, and one released
/// during the pass was found by the read before it.
#[test]
fn status_reports_a_controller_present_at_either_holder_read() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    admit(&store, 0);
    drop(store);
    let during = |take: bool| {
        let held = fs::File::open(&case.state).unwrap();
        if !take {
            held.lock().unwrap();
        }
        let mut done = false;
        observed(
            move |at| {
                if at == Step::List && !done {
                    done = true;
                    if take {
                        held.lock().unwrap();
                    } else {
                        held.unlock().unwrap();
                    }
                }
            },
            || status(&case.state).unwrap(),
        )
    };
    for take in [true, false] {
        let shown = reread(|| during(take), one_holder);
        let holders = shown["lock"]["holders"].as_array().unwrap();
        assert_eq!(holders.len(), 1, "take={take}: {holders:?}");
        assert_eq!(holders[0]["mode"], "exclusive", "take={take}");
        assert_eq!(holders[0]["pid"], std::process::id());
    }
    assert_eq!(status(&case.state).unwrap()["lock"], json!({"holders": []}));
}

#[test]
fn status_ends_with_a_host_fault_at_every_lock_holder_step() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let clean = reread(|| status(&case.state).unwrap(), one_holder);
    assert_eq!(clean["lock"]["holders"][0]["mode"], "exclusive");
    // A read of the lock table that misses the controller's entry makes
    // status read the table again, so one run can take more steps than
    // another. The fault moves to the next step index until a run ends
    // before reaching it, so every index below the shortest run's length
    // takes a fault.
    for index in 0.. {
        let (result, reached) =
            scripted([(index, Outcome::Errno(libc::EIO))], || status(&case.state));
        let result = result.unwrap();
        let Some(at) = reached.get(index) else {
            result.expect("a run that ends before the fault's step succeeds");
            break;
        };
        let error = result.expect_err("a host fault ends the snapshot");
        assert!(error.host_fault(), "{index} {at:?}: {error}");
    }
    drop(store);
}

/// `timeless` normalizes read-dependent fields so snapshots of the same
/// state directory compare equally.
fn timeless(mut shown: Value) -> Value {
    shown["observed_ms"] = Value::Null;
    shown["space"] = Value::Null;
    shown
}

#[test]
fn status_reads_jobs_on_threads_into_the_one_thread_snapshot() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for run in 0..40 {
        let job = admit_counts(&store, run, &[("records", 80 + run % 3)]);
        if run % 5 == 0 {
            continue;
        }
        let (directory, id) = launched(&store, &job, 1);
        if run % 5 == 1 {
            continue;
        }
        let mut done = finished(&id, None);
        if run % 7 == 2 {
            done.class = Class::Violation;
        }
        finish(&store, &directory, &done);
        if run % 5 == 2 {
            continue;
        }
        if run % 5 == 3 {
            store
                .create_once(
                    &jobs(&store, job.job().id().to_string()),
                    &name(&format!("{}{}", job.job().id(), JobResult::SUFFIX)),
                    b"corrupt",
                )
                .unwrap();
            continue;
        }
        settle(&store, &job, JobResult::SUFFIX, &result(&job, 1, done));
    }
    drop(store);
    let (one, reached) = scripted([], || status(&case.state));
    assert!(reached.len() > 400, "{}", reached.len());
    let one = timeless(one.unwrap().unwrap());
    assert_eq!(one["jobs"].as_array().unwrap().len(), 40);
    assert_eq!(one["variants"].as_object().unwrap().len(), 3);
    assert!(!one["release_blockers"].as_array().unwrap().is_empty());
    assert_eq!(timeless(status(&case.state).unwrap()), one);
}

#[test]
fn status_holds_attempt_histories_missing_a_required_predecessor() {
    let cases: [(&[&str], Option<Class>, &str); 4] = [
        (&["intent"], None, "attempt record missing"),
        (&["attempt", "started"], None, "attempt lacks intent"),
        (
            &["attempt", "intent"],
            Some(Class::Pass),
            "pass lacks started witness",
        ),
        (&["attempt"], Some(Class::Violation), "attempt lacks intent"),
    ];
    for (records, class, reason) in cases {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let job = admit(&store, 0);
        let history = history(&store, job.job().id().to_string());
        let directory = open(&store, &history, "0001");
        let id = attempt_id(&job, 1);
        for record in records {
            let created = match *record {
                "attempt" => {
                    store.create_record(&directory, &name("attempt"), &attempt_record(&job, 1))
                }
                "intent" => store.create_record(&directory, &name("intent"), &intent(&id)),
                _ => store.create_record(&directory, &name("started"), &started(&id)),
            };
            created.unwrap();
        }
        if let Some(class) = class {
            let mut done = finished(&id, None);
            done.class = class;
            finish(&store, &directory, &done);
        }
        drop(store);
        let shown = status(&case.state).unwrap();
        let row = row(&shown, &job);
        assert_eq!(row["attempts"][0]["held"], reason, "{row}");
        assert_eq!(row["attempts"][0]["held_code"], "binding");
        assert_eq!(row["state"], "held");
    }
}

#[test]
fn status_gives_a_verified_settlement_precedence_over_held_attempt_evidence() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let settled = admit(&store, 0);
    let (directory, id) = launched(&store, &settled, 1);
    store
        .create_once(&directory, &name("finished"), b"corrupt")
        .unwrap();
    settle(
        &store,
        &settled,
        JobResult::SUFFIX,
        &result(&settled, 1, finished(&id, None)),
    );
    let settling = admit(&store, 1);
    let (directory, id) = launched(&store, &settling, 1);
    finish(&store, &directory, &finished(&id, None));
    let history = case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(
            settling.job().id().to_string(),
        ));
    mkdir(&history.join("0003"));
    settle(
        &store,
        &settling,
        Pin::SUFFIX,
        &Pin {
            result: result(&settling, 1, finished(&id, None)),
        },
    );
    let unattempted = admit(&store, 2);
    let id = attempt_id(&unattempted, 1);
    settle(
        &store,
        &unattempted,
        JobResult::SUFFIX,
        &result(&unattempted, 1, finished(&id, None)),
    );
    drop(store);

    let shown = status(&case.state).unwrap();
    let row_of = |job| row(&shown, job);
    assert_eq!(row_of(&settled)["state"], "settled");
    assert_eq!(row_of(&settled)["attempts"][0]["held_code"], "malformed");
    assert_eq!(row_of(&settling)["state"], "settling");
    assert_eq!(
        row_of(&settling)["attempts_held"]["held"],
        "attempt history has gaps or duplicates"
    );
    let orphan = row_of(&unattempted);
    assert_eq!(orphan["state"], "held");
    assert_eq!(orphan["result"]["attempt"], 1);
    assert_eq!(
        orphan["attempts_held"]["held"],
        "settlement entry has no attempt history"
    );
}

#[test]
fn status_holds_misbound_settlements_and_finishes_in_the_findings_scan() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let foreign = admit(&store, 0);
    let other = admit(&store, 1);
    let (directory, id) = launched(&store, &foreign, 1);
    let mut failed = finished(&id, None);
    failed.class = Class::Violation;
    finish(&store, &directory, &failed);
    let mut misbound = failed.clone();
    misbound.attempt = text(&attempt_id(&other, 1));
    settle(
        &store,
        &foreign,
        JobResult::SUFFIX,
        &result(&foreign, 1, misbound),
    );
    let (directory, _) = launched(&store, &other, 1);
    let mut named = finished(&attempt_id(&foreign, 1), None);
    named.class = Class::Pass;
    finish(&store, &directory, &named);
    let stale = admit(&store, 2);
    let (directory, id) = launched(&store, &stale, 1);
    finish(&store, &directory, &finished(&id, None));
    store
        .create_record(
            &directory,
            &name("captured"),
            &Captured {
                attempt: text(&id),
                finding: None,
                finished: Digest::of(b"another finish"),
            },
        )
        .unwrap();
    let listless = admit(&store, 3);
    launched(&store, &listless, 1);
    let zero = admit(&store, 4);
    let mut failed = finished(&attempt_id(&zero, 0), None);
    failed.class = Class::Violation;
    settle(
        &store,
        &zero,
        Pin::SUFFIX,
        &Pin {
            result: result(&zero, 0, failed),
        },
    );
    let renamed = admit(&store, 5);
    let mut failed = finished(&attempt_id(&renamed, 1), None);
    failed.class = Class::Violation;
    let mut record = result(&renamed, 1, failed.clone());
    record.job = Digest::of(b"other job");
    settle(&store, &renamed, JobResult::SUFFIX, &record);
    let rebound = admit(&store, 6);
    let mut failed = finished(&attempt_id(&rebound, 1), None);
    failed.class = Class::Violation;
    failed.binding = Binding::Matching;
    failed.bound = Some(BoundEvidence {
        artifact: Digest::of(b"artifact"),
        attempt: text(&attempt_id(&rebound, 2)),
        bundle: None,
    });
    settle(
        &store,
        &rebound,
        JobResult::SUFFIX,
        &result(&rebound, 1, failed),
    );
    let unbound = admit(&store, 7);
    let (directory, id) = launched(&store, &unbound, 1);
    let mut matching = finished(&id, None);
    matching.binding = Binding::Matching;
    finish(&store, &directory, &matching);
    let foreign_bound = admit(&store, 8);
    let (directory, id) = launched(&store, &foreign_bound, 1);
    let mut named = finished(&id, None);
    named.binding = Binding::Matching;
    named.bound = Some(BoundEvidence {
        artifact: Digest::of(b"artifact"),
        attempt: text(&attempt_id(&foreign_bound, 2)),
        bundle: None,
    });
    store
        .create_record(&directory, &name("finished"), &named)
        .unwrap();
    let unfinished = admit(&store, 9);
    let (directory, id) = launched(&store, &unfinished, 1);
    store
        .create_record(
            &directory,
            &name("captured"),
            &Captured {
                attempt: text(&id),
                finding: None,
                finished: Digest::of(b"unwritten finish"),
            },
        )
        .unwrap();
    drop(store);
    mkdir(
        &case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                listless.job().id().to_string(),
            ))
            .join("bad name"),
    );

    let shown = status(&case.state).unwrap();
    let held: BTreeSet<_> = shown["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            assert_eq!(row["blocker"], true);
            (
                row["id"].as_str().unwrap().to_owned(),
                row["held"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let job_path = |job: &Admission, suffix: &str| {
        let id = job.job().id().to_string();
        crate::layout::job_file(&id, &format!("{id}{suffix}"))
            .display()
            .to_string()
    };
    let expected: BTreeSet<_> = [
        (
            job_path(&foreign, JobResult::SUFFIX),
            "settlement binding differs".to_owned(),
        ),
        (
            attempt_id(&foreign, 1),
            "authoritative outcome awaits capture".to_owned(),
        ),
        (
            attempt_id(&other, 1),
            "attempt record names another attempt".to_owned(),
        ),
        (
            attempt_id(&stale, 1),
            "capture marker differs from the finish".to_owned(),
        ),
        (
            crate::layout::attempt_path(&listless.job().id().to_string(), 0)
                .parent()
                .unwrap()
                .display()
                .to_string(),
            held_reason(&shown, &listless),
        ),
        (
            job_path(&zero, Pin::SUFFIX),
            "settlement binding differs".to_owned(),
        ),
        (
            job_path(&renamed, JobResult::SUFFIX),
            "settlement binding differs".to_owned(),
        ),
        (
            job_path(&rebound, JobResult::SUFFIX),
            "settlement binding differs".to_owned(),
        ),
        (
            attempt_id(&unbound, 1),
            "finish binding differs from its evidence".to_owned(),
        ),
        (
            attempt_id(&foreign_bound, 1),
            "attempt record names another attempt".to_owned(),
        ),
        (
            attempt_id(&unfinished, 1),
            "capture marker without a finish".to_owned(),
        ),
    ]
    .into();
    assert_eq!(held, expected);
    assert_eq!(row(&shown, &foreign)["state"], "held");
}

/// A root entry or a shard entry that `status` holds as a job row leaves
/// the capture scan without the attempts beneath it, so each held path is a
/// held findings row and a release blocker.
#[test]
fn status_lists_each_held_shard_path_as_a_release_blocker() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = admit(&store, 0);
    let (directory, id) = launched(&store, &job, 1);
    let mut failed = finished(&id, None);
    failed.class = Class::Violation;
    finish(&store, &directory, &failed);
    drop(directory);
    let shown = status(&case.state).unwrap();
    assert_eq!(shown["release_blockers"], json!([id]));
    let own = crate::layout::shard(&job.job().id().to_string());
    let history = format!("attempts/{}", own.as_str());
    fs::rename(case.state.join(&history), case.root.join("moved")).unwrap();
    std::os::unix::fs::symlink(case.root.join("moved"), case.state.join(&history)).unwrap();
    let other = if own.as_str() == "ff" { "fe" } else { "ff" };
    let stray = format!("jobs/{other}/{}.json", job.job().id());
    fs::create_dir_all(case.state.join("jobs").join(other)).unwrap();
    fs::write(case.state.join(&stray), b"stray").unwrap();
    fs::write(case.state.join("jobs/zz"), b"stray").unwrap();
    let orphan = format!("attempts/{other}/{}", job.job().id());
    fs::create_dir_all(case.state.join(&orphan)).unwrap();
    let shown = status(&case.state).unwrap();
    let held = [history.as_str(), stray.as_str(), "jobs/zz", orphan.as_str()];
    for path in held {
        assert!(
            shown["release_blockers"]
                .as_array()
                .unwrap()
                .contains(&json!(path)),
            "{path}: {}",
            shown["release_blockers"]
        );
        assert!(
            shown["findings"].as_array().unwrap().iter().any(|row| {
                row["id"] == path && row["blocker"] == true && row["held"].is_string()
            }),
            "{path}: {}",
            shown["findings"]
        );
    }
}

fn held_reason(shown: &Value, job: &Admission) -> String {
    row(shown, job)["attempts_held"]["held"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn member<'a>(
    id: &'a str,
    kind: FindingKind,
    identity: Option<&'a Text>,
    cause: &'a Text,
    virtual_us: u64,
    profile: &'a Text,
    run: u64,
) -> Member<'a> {
    Member {
        id,
        kind,
        identity,
        cause: Some(cause),
        failure_virtual_us: Some(virtual_us),
        profile,
        run,
        resolved: false,
    }
}

#[test]
fn failure_groups_merge_only_findings_of_one_kind_and_identity() {
    let first = text("02aa0000000000000000000000000000");
    let similar = text("02aa0000000000000000000000000001");
    let (cause, later) = (text("violating Progress"), text("violating Safety"));
    let (get, share) = (text("get"), text("share"));
    let mut resolved = member(
        "c-0001",
        FindingKind::Violation,
        Some(&first),
        &later,
        900,
        &get,
        2,
    );
    resolved.resolved = true;
    let members = vec![
        member(
            "a-0001",
            FindingKind::Violation,
            Some(&first),
            &cause,
            600,
            &get,
            0,
        ),
        member(
            "b-0001",
            FindingKind::Violation,
            Some(&similar),
            &cause,
            600,
            &get,
            0,
        ),
        resolved,
        member(
            "d-0001",
            FindingKind::Violation,
            Some(&first),
            &later,
            700,
            &share,
            0,
        ),
        member(
            "e-0001",
            FindingKind::Panic,
            Some(&first),
            &cause,
            600,
            &get,
            0,
        ),
        member("f-0001", FindingKind::Watchdog, None, &cause, 600, &get, 0),
        member("g-0001", FindingKind::Watchdog, None, &later, 800, &get, 1),
    ];
    let groups = serde_json::to_value(failure_groups(members)).unwrap();
    assert_eq!(
        groups,
        json!([
            {"kind": "violation", "identity": first, "cause": "violating Progress",
             "failure_virtual_us": 600, "findings": ["a-0001", "c-0001", "d-0001"],
             "profiles": ["get", "share"], "runs": [0, 2], "unresolved": 2},
            {"kind": "violation", "identity": similar, "cause": "violating Progress",
             "failure_virtual_us": 600, "findings": ["b-0001"], "profiles": ["get"],
             "runs": [0], "unresolved": 1},
            {"kind": "panic", "identity": first, "cause": "violating Progress",
             "failure_virtual_us": 600, "findings": ["e-0001"], "profiles": ["get"],
             "runs": [0], "unresolved": 1},
            {"kind": "watchdog", "identity": null, "cause": "violating Progress",
             "failure_virtual_us": 600, "findings": ["f-0001"], "profiles": ["get"],
             "runs": [0], "unresolved": 1},
            {"kind": "watchdog", "identity": null, "cause": "violating Safety",
             "failure_virtual_us": 800, "findings": ["g-0001"], "profiles": ["get"],
             "runs": [1], "unresolved": 1},
        ])
    );
}

#[test]
fn overlong_orphan_history_is_held_by_every_read_only_listing() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let history = history(&store, format!("aa{}", "z".repeat(196)));
    open(&store, &history, "0001");
    drop(store);
    let listed = super::findings(&case.state).unwrap();
    assert!(
        listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["held"]
                .as_str()
                .is_some_and(|reason| reason.contains("invalid job identity filename"))),
        "{listed}"
    );
    assert!(status(&case.state).is_ok());
    assert!(super::report(&case.state).is_ok());
}
