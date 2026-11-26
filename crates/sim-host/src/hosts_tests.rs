use super::*;
use crate::health::Health;

const NOW: u64 = 10_000;
const STINT: u64 = 100;

fn id(letter: char) -> String {
    format!("i-0000000{letter}")
}

fn healthy(letter: char, written: u64) -> Value {
    json!({
        "format": 1, "written": written, "instance": id(letter), "build": "b".repeat(64),
        "root": format!("sim.{}.n", id(letter)), "stint_seconds": STINT, "phase": "sweeping",
        "alarm": false, "confirmation": "idle", "held_roots": 0,
        "stint_cpu_usec": 95, "stint_capacity_usec": 100,
    })
}

fn read(letter: char, record: &Value) -> Record {
    bytes(letter, record.to_string().into_bytes())
}

/// A record read under `letter`'s key at the judging clock.
fn bytes(letter: char, bytes: Vec<u8>) -> Record {
    Record::read(id(letter), &bytes, NOW, NOW)
}

fn state(
    records: &[Record],
    newest: &BTreeMap<String, (u64, Option<u64>)>,
) -> Vec<(String, State)> {
    section(records.to_vec(), newest, NOW)
        .rows
        .into_iter()
        .map(|(instance, row)| (instance, row.state))
        .collect()
}

fn one(record: &Value) -> State {
    let states = state(&[read('a', record)], &BTreeMap::new());
    assert_eq!(states.len(), 1, "{states:?}");
    states[0].1
}

#[test]
fn each_record_takes_the_state_of_the_first_rule_it_meets() {
    let fresh = healthy('a', NOW);
    assert_eq!(one(&fresh), State::Active);
    let mut stale = fresh.clone();
    stale["written"] = json!(NOW - 2 * STINT - 1);
    assert_eq!(one(&stale), State::Silent, "rule 3 before rule 5");
    let mut stopped = fresh.clone();
    stopped["phase"] = json!("stopped");
    assert_eq!(
        one(&stopped),
        State::Stopped,
        "rule 4 before the critical phase"
    );
    let mut stale_stopped = stopped.clone();
    stale_stopped["written"] = json!(NOW - 2 * STINT - 1);
    assert_eq!(one(&stale_stopped), State::Silent, "rule 3 before rule 4");
    let mut blocked = fresh.clone();
    blocked["phase"] = json!("blocked");
    blocked["reason"] = json!("the build is not on disk");
    assert_eq!(one(&blocked), State::Unhealthy);
    let mut stale_blocked = blocked.clone();
    stale_blocked["written"] = json!(NOW - 2 * STINT - 1);
    assert_eq!(one(&stale_blocked), State::Silent, "never listed unhealthy");
    let mut degraded = fresh.clone();
    degraded["upload_error"] = json!("roots: refused");
    assert_eq!(one(&degraded), State::Degraded);
    let mut foreign = fresh.clone();
    foreign["instance"] = json!(id('b'));
    assert_eq!(one(&foreign), State::Missing);
    let mut nameless = fresh.clone();
    nameless
        .as_object_mut()
        .expect("an object")
        .remove("instance");
    for record in [&foreign, &nameless] {
        let mut stale = record.clone();
        stale["written"] = json!(NOW - 2 * STINT - 1);
        assert_eq!(one(&stale), State::Missing, "rule 2 before rule 3");
    }
    let mut stopped_rootless = stopped.clone();
    stopped_rootless
        .as_object_mut()
        .expect("an object")
        .remove("stint_seconds");
    assert_eq!(
        one(&stopped_rootless),
        State::Unhealthy,
        "rule 4 needs a stint length"
    );
    for phase in ["stopped", "sweeping"] {
        let mut undated = fresh.clone();
        undated["phase"] = json!(phase);
        undated
            .as_object_mut()
            .expect("an object")
            .remove("written");
        assert_eq!(
            one(&undated),
            State::Unhealthy,
            "a record in phase {phase} with no written"
        );
    }
    let all = [
        read('a', &fresh),
        read('b', &healthy('b', NOW - 2 * STINT - 1)),
        read('c', &{
            let mut stopped = healthy('c', NOW);
            stopped["phase"] = json!("stopped");
            stopped
        }),
        read('d', &{
            let mut degraded = healthy('d', NOW);
            degraded["fetch_error"] = json!("refused");
            degraded
        }),
        read('e', &{
            let mut blocked = healthy('e', NOW);
            blocked["phase"] = json!("blocked");
            blocked
        }),
        Record::Unread {
            instance: id('f'),
            size: Some(health::BOUND + 1),
        },
    ];
    let section = section(all, &BTreeMap::new(), NOW);
    assert_eq!(
        section.counts(),
        BTreeMap::from([
            ("active", 1),
            ("degraded", 1),
            ("missing", 1),
            ("silent", 1),
            ("stopped", 1),
            ("unhealthy", 1),
        ])
    );
}

#[test]
fn a_record_without_evidence_is_never_active_or_degraded() {
    let fresh = healthy('a', NOW);
    let mut nameless = fresh.clone();
    nameless
        .as_object_mut()
        .expect("an object")
        .remove("instance");
    let mut ahead = fresh.clone();
    ahead["written"] = json!(NOW + CLOCK_SKEW_S + 1);
    let fields = [
        "format",
        "written",
        "instance",
        "build",
        "root",
        "assignment",
        "assignment_error",
        "upload_error",
        "fetch_error",
        "cleanup_error",
        "stint",
        "stint_seconds",
        "phase",
        "reason",
        "sweep_overdue",
        "exits",
        "alarm",
        "confirmation",
        "confirmation_reason",
        "confirming",
        "confirm_exit_root",
        "held_roots",
        "held_root_names",
        "share_stint",
        "stint_cpu_usec",
        "stint_capacity_usec",
        "cpu_usec",
        "capacity_usec",
    ];
    let positional: Vec<Value> = fields.iter().map(|field| fresh[*field].clone()).collect();
    let positional = serde_json::to_vec(&positional).expect("an array");
    assert!(
        serde_json::from_slice::<Health>(&positional).is_ok(),
        "the array parses as a record, so only the object check refuses it"
    );
    let mut padded = fresh.to_string().into_bytes();
    padded.resize(health::BOUND as usize, b' ');
    assert_eq!(padded.len() as u64, health::BOUND);
    assert_eq!(
        state(&[bytes('a', padded.clone())], &BTreeMap::new()),
        [(id('a'), State::Active)],
        "a record of exactly the bound is judged"
    );
    padded.push(b' ');
    for record in [
        Record::Unread {
            instance: id('a'),
            size: Some(health::BOUND + 1),
        },
        Record::Unread {
            instance: id('a'),
            size: None,
        },
        bytes('a', b"{\"format\": 1".to_vec()),
        bytes('a', Vec::new()),
        bytes('a', b" \n".to_vec()),
        bytes('a', b"[1]".to_vec()),
        bytes('a', positional),
        bytes('a', padded),
        read('a', &nameless),
        read('a', &ahead),
    ] {
        let states = state(std::slice::from_ref(&record), &BTreeMap::new());
        assert_eq!(states, [(id('a'), State::Missing)], "{record:?}");
    }
    let mut inside = fresh.clone();
    inside["written"] = json!(NOW + 1);
    assert_eq!(one(&inside), State::Active, "one second ahead is age 0");
    let mut edge = fresh.clone();
    edge["written"] = json!(NOW + CLOCK_SKEW_S);
    assert_eq!(one(&edge), State::Active);
    let mut longest = fresh.clone();
    longest["stint_seconds"] = json!(assignment::SECONDS_MAX);
    assert_eq!(one(&longest), State::Active, "the longest stint length");
    for stint in [Value::Null, json!(0), json!(assignment::SECONDS_MAX + 1)] {
        let mut record = fresh.clone();
        record["stint_seconds"] = stint.clone();
        assert_eq!(one(&record), State::Unhealthy, "{stint}");
        let mut old = record.clone();
        old["written"] = json!(0);
        assert_eq!(one(&old), State::Unhealthy, "{stint} at any age");
    }
    let mut claims_b = healthy('b', NOW);
    claims_b["instance"] = json!(id('b'));
    let stale_b = healthy('b', NOW - 2 * STINT - 1);
    let records = [read('a', &claims_b), read('b', &stale_b)];
    assert_eq!(
        state(&records, &BTreeMap::new()),
        [(id('a'), State::Missing), (id('b'), State::Silent)],
        "a record under key A that names B leaves B judged by its own record"
    );
}

#[test]
fn silent_is_raised_only_by_a_record_older_than_two_stint_lengths() {
    let mut edge = healthy('a', NOW - 2 * STINT);
    assert_eq!(one(&edge), State::Active, "at two stint lengths");
    edge["written"] = json!(NOW - 2 * STINT - 1);
    assert_eq!(one(&edge), State::Silent);
    for phase in [
        "starting", "sweeping", "waiting", "held", "full", "blocked", "stopped",
    ] {
        let mut fresh = healthy('a', NOW);
        fresh["phase"] = json!(phase);
        assert_ne!(
            one(&fresh),
            State::Silent,
            "a fresh record in phase {phase}"
        );
        let mut stale = healthy('a', NOW - 2 * STINT - 1);
        stale["phase"] = json!(phase);
        assert_eq!(
            one(&stale),
            State::Silent,
            "a stale record in phase {phase}"
        );
    }
    let newest = BTreeMap::from([(id('a'), (0, Some(STINT)))]);
    assert_eq!(
        state(&[read('a', &healthy('a', NOW))], &newest),
        [(id('a'), State::Active)],
        "a stale snapshot beside a fresh record"
    );
}

#[test]
fn a_host_without_a_record_is_missing_only_while_its_newest_snapshot_is_fresh() {
    let newest = BTreeMap::from([
        (id('a'), (NOW - 2 * STINT, Some(STINT))),
        (id('b'), (NOW - 2 * STINT - 1, Some(STINT))),
        (id('c'), (NOW, None)),
        (id('d'), (NOW + CLOCK_SKEW_S, Some(STINT))),
        (id('e'), (NOW, Some(0))),
        (id('f'), (NOW, Some(assignment::SECONDS_MAX + 1))),
        (id('g'), (NOW, Some(assignment::SECONDS_MAX))),
    ]);
    let section = section([], &newest, NOW);
    let states: Vec<_> = section
        .rows
        .iter()
        .map(|(instance, row)| (instance.clone(), row.state))
        .collect();
    assert_eq!(
        states,
        [
            (id('a'), State::Missing),
            (id('d'), State::Missing),
            (id('g'), State::Missing)
        ],
        "a retired host with only older snapshots, or snapshots with no valid stint length, has no row"
    );
    let error = "the host stores root snapshots and no health record";
    assert_eq!(
        serde_json::to_value(&section.rows[&id('a')]).expect("a row"),
        json!({
            "build": "unknown", "error": error, "phase": "unknown", "reason": "unknown",
            "reasons": [error], "root": "unknown", "share": "unknown", "state": "missing",
            "stint_seconds": "unknown", "written": "unknown",
        })
    );
    assert_eq!(
        state(&[read('a', &healthy('a', NOW))], &newest)[0],
        (id('a'), State::Active),
        "a record replaces the snapshot rule"
    );
}

#[test]
fn a_key_is_checked_for_its_instance_before_any_read() {
    assert_eq!(
        named("hosts/i-0000000a/health.json"),
        Some(("i-0000000a", true))
    );
    assert_eq!(
        named("hosts/i-0000000a/other.json"),
        Some(("i-0000000a", false))
    );
    assert_eq!(named("hosts/i-0000000a"), Some(("i-0000000a", false)));
    assert_eq!(
        named(&health::key("i-0c9d77352d2d68bfd")),
        Some(("i-0c9d77352d2d68bfd", true)),
        "the key the runner writes is a record's key"
    );
    for key in [
        "hosts/not-an-id/health.json",
        "hosts//health.json",
        "hosts/I-0000000A/health.json",
        "hosts/i-0000000g/health.json",
        "hosts/health.json",
    ] {
        assert_eq!(named(key), None, "{key}");
    }
    let unnamed = |key: &str| Record::Unnamed { key: key.into() };
    let keys = ["hosts/not-an-id/health.json", "hosts/x/y", "hosts/a"];
    let forward: Vec<Record> = keys.iter().map(|key| unnamed(key)).collect();
    let mut reversed = forward.clone();
    reversed.reverse();
    let section = section(forward, &BTreeMap::new(), NOW);
    assert!(section.rows.is_empty());
    assert_eq!(
        section.unnamed,
        ["hosts/a", "hosts/not-an-id/health.json", "hosts/x/y"]
            .map(|key| json!({"key": key, "error": "its instance part is no instance id"}))
    );
    assert_eq!(
        super::section(reversed, &BTreeMap::new(), NOW),
        section,
        "the unnamed keys take one order under any listing order"
    );
}

#[test]
fn a_row_prints_the_records_fields_and_unknown_for_each_it_lacks() {
    let mut record = healthy('a', NOW);
    record["phase"] = json!("blocked");
    record["reason"] = json!("builds/x is missing");
    record.as_object_mut().expect("an object").remove("build");
    let row = &section([read('a', &record)], &BTreeMap::new(), NOW).rows[&id('a')];
    assert_eq!(row.state, State::Unhealthy);
    assert_eq!(
        serde_json::to_value(row).expect("a row"),
        json!({
            "build": "unknown", "error": null, "phase": "blocked",
            "reason": "builds/x is missing", "reasons": ["phase blocked"],
            "root": format!("sim.{}.n", id('a')), "share": 0.95, "state": "unhealthy",
            "stint_seconds": STINT, "written": NOW,
        })
    );
}

#[test]
fn a_record_past_the_bound_names_its_size_only_when_the_listing_gave_it() {
    let rows = section(
        [
            Record::Unread {
                instance: id('a'),
                size: Some(health::BOUND + 9),
            },
            Record::Unread {
                instance: id('b'),
                size: None,
            },
        ],
        &BTreeMap::new(),
        NOW,
    )
    .rows;
    let errors: Vec<_> = rows.values().map(|row| row.error.clone()).collect();
    assert_eq!(
        errors,
        [
            Some(format!(
                "the record holds {} bytes, more than {}",
                health::BOUND + 9,
                health::BOUND
            )),
            Some(format!(
                "the record holds more than {} bytes",
                health::BOUND
            )),
        ]
    );
}

fn texts(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(values) => values.iter().for_each(|value| texts(value, out)),
        Value::Object(fields) => fields.values().for_each(|value| texts(value, out)),
        _ => {}
    }
}

#[test]
fn a_read_record_keeps_its_judgment_and_none_of_its_bytes() {
    let compact = healthy('a', NOW).to_string().into_bytes();
    let mut padded = compact.clone();
    padded.resize(health::BOUND as usize, b' ');
    let judged = Record::read(id('a'), &compact, NOW, NOW);
    assert_eq!(Record::read(id('a'), &padded, NOW, NOW), judged);
    let Record::Judged { instance, row } = judged else {
        panic!("a read record is judged: {judged:?}");
    };
    assert_eq!((instance, row.state), (id('a'), State::Active));
}

#[test]
fn a_row_keeps_each_text_up_to_the_text_bound() {
    let long = |letter: char| letter.to_string().repeat(health::TEXT_MAX + 1);
    let mut record = healthy('a', NOW);
    record["build"] = json!(long('b'));
    record["root"] = json!(long('r'));
    record["reason"] = json!(long('x'));
    record["phase"] = json!(long('p'));
    let mut unparsed = healthy('b', NOW);
    unparsed["stint_cpu_usec"] = json!(long('u'));
    let rows = section(
        [read('a', &record), read('b', &unparsed)],
        &BTreeMap::new(),
        NOW,
    )
    .rows;
    let shown = |length: usize| json!(format!("a text of {length} bytes"));
    let row = serde_json::to_value(&rows[&id('a')]).expect("a row");
    assert_eq!(row["state"], "unhealthy");
    for field in ["build", "root", "reason", "phase"] {
        assert_eq!(row[field], shown(health::TEXT_MAX + 1), "{field}");
    }
    assert_eq!(
        row["reasons"],
        json!([shown(health::TEXT_MAX + 1 + "phase ".len())])
    );
    let row = serde_json::to_value(&rows[&id('b')]).expect("a row");
    assert_eq!(row["state"], "missing");
    let error = row["error"].as_str().expect("an error");
    assert!(
        error.starts_with("a text of ") && error.ends_with(" bytes"),
        "{error}"
    );
    assert_eq!(row["reasons"], json!([error]));
    for row in rows.values() {
        let mut out = Vec::new();
        texts(&serde_json::to_value(row).expect("a row"), &mut out);
        for text in out {
            assert!(text.len() <= health::TEXT_MAX, "{} bytes", text.len());
        }
    }
}

/// A host clock ahead of the report is judged against the clock read
/// after the record's download, and its age against the judging clock.
#[test]
fn the_ahead_check_uses_the_clock_read_after_the_download() {
    let observed = NOW + 600;
    let judged = |written: u64| {
        let bytes = healthy('a', written).to_string().into_bytes();
        let record = Record::read(id('a'), &bytes, observed, NOW);
        state(&[record], &BTreeMap::new())[0].1
    };
    assert_eq!(judged(observed + CLOCK_SKEW_S), State::Active);
    assert_eq!(judged(NOW + CLOCK_SKEW_S + 1), State::Active);
    assert_eq!(judged(observed + CLOCK_SKEW_S + 1), State::Missing);
    assert_eq!(
        judged(NOW - 2 * STINT - 1),
        State::Silent,
        "the age is judged at the clock read before the listing"
    );
}
