use super::*;

const NOW: u64 = 1_794_873_600;

fn group(profile: &str, key: &str, root: &str) -> Value {
    json!({
        "count": 2, "key": key, "profile": profile, "roots": [root],
        "rerun": {"campaign": root, "counts": {"watchdog": 900}, "profile": profile, "run": 7},
    })
}

fn document(builds: Value, hosts: Value) -> Value {
    json!({
        "builds": builds, "exit": 0, "flags": [], "format": 1,
        "host_counts": {"active": 1}, "hosts": hosts, "roots": {},
    })
}

/// Each failure group `document` shows under a build, as that build's
/// listing of the group's profile and key.
fn listings(document: &Value) -> Vec<Listing<'_, &Value>> {
    let mut listings = Vec::new();
    for (build, entry) in document["builds"].as_object().into_iter().flatten() {
        for group in entry[FAILURES].as_array().into_iter().flatten() {
            listings.push(Listing {
                build,
                profile: group["profile"].as_str().expect("a profile"),
                key: group["key"].as_str().expect("a key"),
                group,
            });
        }
    }
    listings
}

/// The writes [`decide`] derives from `document` and the failure groups
/// it shows.
fn decided(
    document: &Value,
    known: &BTreeSet<String>,
    open: &BTreeSet<Alert>,
    digested: Option<&str>,
    now: u64,
) -> Writes {
    decide(document, listings(document), known, open, digested, now)
        .expect("every group serializes")
}

fn row(state: &str, reasons: &[&str]) -> Value {
    json!({"state": state, "reasons": reasons})
}

fn alert(flag: &str, instance: &str) -> Alert {
    Alert {
        flag: flag.to_owned(),
        instance: instance.to_owned(),
    }
}

#[test]
fn an_identity_is_the_sha256_of_profile_zero_byte_key() {
    assert_eq!(
        identity("p", "k"),
        crate::file::sha256(b"p\0k"),
        "the stored contract"
    );
    assert_ne!(identity("p\0k", ""), identity("p", "\0k"));
    let id = identity("p", "k");
    assert_eq!(failure_id(&failure_key(&id)), Some(id.as_str()));
    assert_eq!(failure_id("events/failure-x.json"), None);
    assert_eq!(failure_id("events/hosts-1.json"), None);
}

#[test]
fn the_day_is_the_utc_calendar_day_of_the_clock() {
    for (now, expected) in [
        (0, "1970-01-01"),
        (86_399, "1970-01-01"),
        (86_400, "1970-01-02"),
        (951_782_400, "2000-02-29"),
        (1_794_873_600, "2026-11-17"),
        (1_794_959_999, "2026-11-17"),
        (4_107_542_399, "2100-02-28"),
        (4_107_542_400, "2100-03-01"),
    ] {
        assert_eq!(day(now), expected, "{now}");
    }
}

#[test]
fn a_cycle_creates_at_most_sixteen_records_lowest_id_first() {
    let groups: Vec<Value> = (0..20)
        .map(|index| group("p", &format!("k{index}"), "r"))
        .collect();
    let document = document(json!({"b": {"failures": groups}}), json!({}));
    let mut known = BTreeSet::new();
    let first = decided(&document, &known, &BTreeSet::new(), None, NOW);
    assert_eq!(first.failures.len(), RECORDS);
    assert_eq!(first.waiting, 4);
    let ids: Vec<&String> = first.failures.iter().map(|record| &record.id).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "lowest id first");
    let all: BTreeSet<String> = (0..20)
        .map(|index| identity("p", &format!("k{index}")))
        .collect();
    assert_eq!(
        ids.iter().map(|id| (*id).clone()).collect::<BTreeSet<_>>(),
        all.iter().take(RECORDS).cloned().collect(),
        "the sixteen lowest of the twenty"
    );
    known.extend(first.failures.iter().map(|record| record.id.clone()));
    let second = decided(&document, &known, &BTreeSet::new(), None, NOW);
    assert_eq!(second.failures.len(), 4);
    assert_eq!(second.waiting, 0);
    known.extend(second.failures.iter().map(|record| record.id.clone()));
    assert_eq!(known, all, "twenty records after two cycles");
    let third = decided(&document, &known, &BTreeSet::new(), None, NOW);
    assert!(third.failures.is_empty());
}

#[test]
fn a_record_carries_the_group_of_the_lowest_build_that_lists_it() {
    let (low, high) = ("1".repeat(64), "2".repeat(64));
    let document = document(
        json!({
            &high: {"failures": [group("p", "k", "sim.i-0000000b.bb")]},
            &low: {"failures": [group("p", "k", "sim.i-0000000a.aa")]},
        }),
        json!({}),
    );
    let ascending = listings(&document);
    assert_eq!(
        ascending[0].build, low,
        "the listings start at the low build"
    );
    let descending = listings(&document).into_iter().rev().collect();
    for (order, listed) in [("ascending", ascending), ("descending", descending)] {
        let writes = decide(
            &document,
            listed,
            &BTreeSet::new(),
            &BTreeSet::new(),
            None,
            NOW,
        )
        .expect("every group serializes");
        assert_eq!(
            writes.failures.len(),
            1,
            "{order}: one identity across builds"
        );
        let Record { id, body: record } = &writes.failures[0];
        assert_eq!(id, &identity("p", "k"));
        assert_eq!(failure_key(id), format!("events/failure-{id}.json"));
        let expected = group("p", "k", "sim.i-0000000a.aa");
        assert_eq!(record["build"], low.as_str(), "{order}");
        for field in ["profile", "key", "count", "roots", "rerun"] {
            assert_eq!(record[field], expected[field], "{order}: {field}");
        }
        assert_eq!(record["rerun"]["campaign"], "sim.i-0000000a.aa", "{order}");
    }
}

/// A failure group that counts how often it is serialized.
struct Counted<'a> {
    group: &'a Value,
    serialized: &'a std::cell::Cell<usize>,
}

impl Serialize for Counted<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.serialized.set(self.serialized.get() + 1);
        self.group.serialize(serializer)
    }
}

// Serializing a group copies its root's counts, so the groups a cycle
// serializes bound the count copies its decision step makes. Twenty
// identities are due and two builds list each one, and the cycle
// serializes sixteen groups: one for each record it creates, each the low
// build's.
#[test]
fn a_cycle_serializes_only_the_groups_it_records() {
    let (low, high) = ("1".repeat(64), "2".repeat(64));
    let groups = |root: &str| -> Vec<Value> {
        (0..20)
            .map(|index| group("p", &format!("k{index}"), root))
            .collect()
    };
    let document = document(
        json!({
            &low: {"failures": groups("sim.i-0000000a.aa")},
            &high: {"failures": groups("sim.i-0000000b.bb")},
        }),
        json!({}),
    );
    let serialized = std::cell::Cell::new(0);
    let counted = || {
        listings(&document).into_iter().map(|listing| Listing {
            build: listing.build,
            profile: listing.profile,
            key: listing.key,
            group: Counted {
                group: listing.group,
                serialized: &serialized,
            },
        })
    };
    let mut known = BTreeSet::new();
    let first = decide(&document, counted(), &known, &BTreeSet::new(), None, NOW)
        .expect("every group serializes");
    assert_eq!((first.failures.len(), first.waiting), (RECORDS, 4));
    assert_eq!(
        serialized.get(),
        RECORDS,
        "one serialization for each record, none for a waiting identity or the high build"
    );
    for record in &first.failures {
        let body = &record.body;
        assert_eq!(body["build"], low.as_str(), "{body}");
        assert_eq!(body["roots"], json!(["sim.i-0000000a.aa"]), "{body}");
        assert_eq!(body["rerun"]["counts"], json!({"watchdog": 900}), "{body}");
        assert_eq!(body["count"], 2, "{body}");
    }
    known.extend(first.failures.iter().map(|record| record.id.clone()));
    let second = decide(&document, counted(), &known, &BTreeSet::new(), None, NOW)
        .expect("every group serializes");
    assert_eq!((second.failures.len(), second.waiting), (4, 0));
    assert_eq!(serialized.get(), 20, "four more, for the four records");
    known.extend(second.failures.iter().map(|record| record.id.clone()));
    let third = decide(&document, counted(), &known, &BTreeSet::new(), None, NOW)
        .expect("every group serializes");
    assert!(third.failures.is_empty());
    assert_eq!(
        serialized.get(),
        20,
        "a known identity's group is never serialized"
    );
}

#[test]
fn an_alert_opens_once_and_again_only_after_it_closed_or_its_state_was_lost() {
    let unhealthy = document(
        json!({}),
        json!({"i-0000000a": row("unhealthy", &["phase blocked"]),
               "i-0000000b": row("active", &[]), "i-0000000c": row("stopped", &["phase stopped"]),
               "i-0000000d": row("degraded", &["upload error"])}),
    );
    let first = decided(&unhealthy, &BTreeSet::new(), &BTreeSet::new(), None, NOW);
    let (key, event) = first.hosts.clone().expect("an event");
    assert_eq!(key, format!("events/hosts-{NOW}.json"));
    assert_eq!(
        event["alerts"],
        json!([{"flag": "unhealthy", "instance": "i-0000000a", "reasons": ["phase blocked"]}])
    );
    assert_eq!(
        first.open,
        BTreeSet::from([alert("unhealthy", "i-0000000a")])
    );
    let unchanged = decided(&unhealthy, &BTreeSet::new(), &first.open, None, NOW + 300);
    assert_eq!(
        unchanged.hosts, None,
        "an unchanged condition gives one event"
    );
    assert_eq!(unchanged.open, first.open);
    let recovered = document(json!({}), json!({"i-0000000a": row("active", &[])}));
    let closed = decided(
        &recovered,
        &BTreeSet::new(),
        &unchanged.open,
        None,
        NOW + 600,
    );
    assert_eq!(closed.hosts, None);
    assert!(closed.open.is_empty());
    let again = decided(&unhealthy, &BTreeSet::new(), &closed.open, None, NOW + 900);
    assert!(
        again.hosts.is_some(),
        "a host that recovered and turned unhealthy again"
    );
    let lost = decided(
        &unhealthy,
        &BTreeSet::new(),
        &BTreeSet::new(),
        None,
        NOW + 1_200,
    );
    assert!(
        lost.hosts.is_some(),
        "a lost alert state stores the alerts once more"
    );
    let many = document(
        json!({}),
        json!({"i-0000000a": row("silent", &["stale"]), "i-0000000b": row("missing", &["e"]),
               "i-0000000c": row("unhealthy", &[])}),
    );
    let partly = BTreeSet::from([alert("silent", "i-0000000a")]);
    let writes = decided(&many, &BTreeSet::new(), &partly, None, NOW);
    let listed: Vec<&Value> = writes.hosts.as_ref().expect("an event").1["alerts"]
        .as_array()
        .expect("alerts")
        .iter()
        .map(|alert| &alert["instance"])
        .collect();
    assert_eq!(listed, [&json!("i-0000000b"), &json!("i-0000000c")]);
    assert_eq!(writes.open.len(), 3);
}

#[test]
fn the_summary_is_due_once_per_day_of_the_clock_input() {
    let mut document = document(
        json!({"b": {"roots": 2, "runs": 10, "failures": [group("p", "k", "r")],
                     "findings": [], "unkeyed": []}}),
        json!({}),
    );
    let known = BTreeSet::from(["x".to_owned()]);
    let writes = decided(&document, &known, &BTreeSet::new(), None, NOW);
    let Summary { day, body } = writes.digest.expect("a summary");
    assert_eq!(digest_key(&day), "events/digest-2026-11-17.json");
    assert_eq!(day, "2026-11-17");
    assert_eq!(body["host_counts"], json!({"active": 1}));
    assert_eq!(body["builds"], json!({"b": {"roots": 2, "runs": 10}}));
    assert_eq!(
        body["failure_identities"], 2,
        "the known one and the one created"
    );
    assert_eq!(body["flags"], json!({}));
    document["flags"] = json!([
        {"root": "sim.i-0000000a.aa", "flag": "missing", "detail": "sweep_status"},
        {"root": "sim.i-0000000b.bb", "flag": "missing", "detail": "elapsed_s"},
        {"root": "sim.i-0000000a.aa", "flag": "alarm", "detail": "a watchdog"},
    ]);
    let flagged = decided(&document, &known, &BTreeSet::new(), None, NOW);
    assert_eq!(
        flagged.digest.expect("a summary").body["flags"],
        json!({"alarm": 1, "missing": 2}),
        "flags are counted by kind"
    );
    let stored = decided(
        &document,
        &known,
        &BTreeSet::new(),
        Some("2026-11-17"),
        NOW + 3_600,
    );
    assert_eq!(stored.digest, None, "a summary of the day is known stored");
    let next = decided(
        &document,
        &known,
        &BTreeSet::new(),
        Some("2026-11-17"),
        NOW + 86_400,
    );
    assert_eq!(next.digest.expect("the next day").day, "2026-11-18");
}
