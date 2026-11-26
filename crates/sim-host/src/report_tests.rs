use super::*;

const NOW: u64 = 10_000;

fn build(digit: char) -> String {
    digit.to_string().repeat(64)
}

fn host(letter: char) -> String {
    format!("i-0000000{letter}")
}

fn name(letter: char, nonce: &str) -> String {
    format!("sim.{}.{nonce}", host(letter))
}

/// A record that `sim-host status` rates ok at `written`.
fn record(instance: &str, written: u64) -> Value {
    json!({
        "format": 1, "written": written, "instance": instance, "stint_seconds": 3600,
        "phase": "sweeping", "held_roots": 0, "stint_cpu_usec": 95, "stint_capacity_usec": 100,
    })
}

fn stored(instance: &str, record: &Value, now: u64) -> Record {
    Record::read(instance.to_owned(), record.to_string().as_bytes(), NOW, now)
}

/// Folds `roots` with `records` as the host section's input.
fn fold_with<'r>(
    records: Vec<Record>,
    roots: impl IntoIterator<Item = &'r Root>,
    only: Option<&str>,
    now: u64,
) -> (u8, Value) {
    let mut report = Report::new(only, now);
    for root in roots {
        report.add(root);
    }
    let (code, document) = report.finish(records);
    let document = serde_json::to_value(&document).expect("the document serializes");
    (code, document)
}

/// Folds `roots` with an ok record, written at `now`, for every host a
/// root's envelope names, so only the roots raise flags.
fn fold<'r>(
    roots: impl IntoIterator<Item = &'r Root> + Clone,
    only: Option<&str>,
    now: u64,
) -> (u8, Value) {
    let hosts: BTreeSet<String> = roots
        .clone()
        .into_iter()
        .filter_map(|root| root.status.read().ok()?.host.get().cloned())
        .collect();
    let records = hosts
        .iter()
        .map(|host| stored(host, &record(host, now), now))
        .collect();
    fold_with(records, roots, only, now)
}

fn read_status(status: &Value) -> Object<Envelope> {
    parse(&Object::Read(status.to_string().into_bytes()))
}

fn root(status: Value, suspects: &str) -> Root {
    root_with(
        status,
        suspects,
        json!({"findings": [], "release_blockers": []}),
    )
}

fn root_with(status: Value, suspects: &str, findings: Value) -> Root {
    Root {
        campaign: status["campaign"].as_str().expect("a campaign").to_owned(),
        observed: NOW,
        status: read_status(&status),
        payload: Some(Payload {
            suspects: Object::Read(suspects.as_bytes().to_vec()),
            findings: parse(&Object::Read(findings.to_string().into_bytes())),
        }),
    }
}

fn status(letter: char, nonce: &str, build: &str, runs: u64, pass: u64) -> Value {
    let campaign = name(letter, nonce);
    json!({
        "format": 1, "build": build, "host": host(letter), "campaign": campaign, "stint": 3,
        "stint_seconds": 3600, "written": NOW, "cpu_usec": 300, "capacity_usec": 1000,
        "sweep_status": {
            "campaign": campaign, "counts": {"watchdog": 900},
            "runs": runs, "pass": pass, "uncredited": 1, "suspects": 2,
            "replays": 4, "elapsed_s": 10.0, "controls": {"missed": 0}, "histories": {"missed": 0},
            "profiles": {"p": {"suspect_keys": {}}},
        },
    })
}

fn line(campaign: &str, build: &str, profile: &str, run: u64, key: &str) -> String {
    format!(
        "{}\n",
        json!({"campaign": campaign, "build": build, "profile": profile, "run": run,
               "counts": {"watchdog": 900}, "seed": 7, "key": key})
    )
}

fn flags(report: &Value) -> Vec<(Value, String)> {
    report["flags"]
        .as_array()
        .expect("flags")
        .iter()
        .map(|flag| {
            (
                flag["root"].clone(),
                flag["flag"].as_str().expect("a name").to_owned(),
            )
        })
        .collect()
}

fn on(campaign: &str, flag: &str) -> (Value, String) {
    (json!(campaign), flag.to_owned())
}

#[test]
fn sums_stay_per_build_and_each_share_is_a_ratio_of_sums() {
    let (one, two) = (build('1'), build('2'));
    let mut b = status('b', "b", &one, 50, 40);
    b["cpu_usec"] = json!(600);
    b["capacity_usec"] = json!(3000);
    b["sweep_status"]["elapsed_s"] = json!(30.0);
    let roots = [
        root(status('a', "a", &one, 100, 90), ""),
        root(b, ""),
        root(status('a', "c", &two, 7, 7), ""),
    ];
    let (code, report) = fold(&roots, None, NOW);
    assert_eq!(code, 0, "{report:#}");
    let first = &report["builds"][&one];
    assert_eq!(first["runs"], 150);
    assert_eq!(first["pass"], 130);
    assert_eq!(first["unproven"], 0, "no root of the build is alarmed");
    assert_eq!(first["hosts"], 2);
    assert_eq!(first["cpu_share"], 0.225, "900 / 4000, not the mean 0.25");
    assert_eq!(first["runs_per_s"], 3.75, "150 / 40, not the mean 5.83");
    assert_eq!(report["builds"][&two]["runs"], 7);
    assert_eq!(report["builds"][&two]["cpu_share"], 0.3);
}

#[test]
fn the_fold_is_byte_equal_under_every_order_of_its_roots() {
    let one = build('1');
    let mut roots = Vec::new();
    for (index, letter) in ['a', 'b', 'c'].into_iter().enumerate() {
        let campaign = name(letter, "n");
        let mut status = status(letter, "n", &one, 10, 9);
        status["sweep_status"]["elapsed_s"] = json!(0.1 * (index as f64 + 1.0));
        status["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"k": 1});
        status["written"] = json!(NOW - index as u64);
        let findings = json!({"findings": [{"id": format!("f{index}"), "resolved": false,
            "dispositions": []}], "release_blockers": []});
        let list = line(&campaign, &one, "p", 50 - index as u64, "k");
        roots.push(root_with(status, &list, findings));
    }
    let mut overflow = status('d', "n", &one, u64::MAX, 9);
    overflow["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"k": u64::MAX});
    let list = line(&name('d', "n"), &one, "p", 1, "k");
    roots.push(root(overflow, &list));
    let expected = fold(&roots, None, NOW).1.to_string();
    for order in [[3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1], [0, 1, 3, 2]] {
        let permuted = order.iter().map(|&index| &roots[index]);
        assert_eq!(
            fold(permuted, None, NOW).1.to_string(),
            expected,
            "{order:?}"
        );
    }
    let report: Value = serde_json::from_str(&expected).expect("json");
    let first = &report["builds"][&one];
    assert_eq!(first["elapsed_s"], 10.6);
    assert_eq!(first["runs"], "unknown");
    assert_eq!(first["failures"][0]["count"], "unknown");
    assert_eq!(first["failures"][0]["rerun"]["campaign"], name('a', "n"));
    assert_eq!(first["failures"][0]["rerun"]["run"], 50);
    assert_eq!(first["findings"].as_array().expect("findings").len(), 3);
    let overflowed: Vec<&Value> = report["flags"]
        .as_array()
        .expect("flags")
        .iter()
        .filter(|flag| flag["root"].is_null())
        .map(|flag| &flag["detail"]["field"])
        .collect();
    assert_eq!(
        overflowed,
        [&json!("runs"), &json!({"key": "k", "profile": "p"})]
    );
}

#[test]
fn failures_group_by_build_profile_and_key() {
    let (one, two) = (build('1'), build('2'));
    let (a, b) = (name('a', "a"), name('b', "b"));
    let mut first = status('a', "a", &one, 10, 9);
    first["sweep_status"]["profiles"] = json!({
        "p": {"suspect_keys": {"k": 3, "j": 1}}, "q": {"suspect_keys": {"k": 5}},
    });
    let mut second = status('b', "b", &two, 10, 9);
    second["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"k": 7});
    let list = [
        line(&a, &one, "p", 50, "k"),
        line(&a, &one, "p", 40, "k"),
        line(&a, &one, "p", 60, "j"),
        line(&a, &one, "q", 9, "k"),
    ]
    .concat();
    let roots = [
        root(first, &list),
        root(second, &line(&b, &two, "p", 1, "k")),
    ];
    let (code, report) = fold(&roots, None, NOW);
    assert_eq!(code, 0, "{report:#}");
    let rerun = |campaign: &str, profile: &str, run: u64| json!({"campaign": campaign, "profile": profile, "run": run, "counts": {"watchdog": 900}});
    assert_eq!(
        report["builds"][&one]["failures"],
        json!([
            {"profile": "p", "key": "j", "count": 1, "roots": [a], "rerun": rerun(&a, "p", 60)},
            {"profile": "p", "key": "k", "count": 3, "roots": [a], "rerun": rerun(&a, "p", 40)},
            {"profile": "q", "key": "k", "count": 5, "roots": [a], "rerun": rerun(&a, "q", 9)},
        ])
    );
    assert_eq!(
        report["builds"][&two]["failures"],
        json!([{"profile": "p", "key": "k", "count": 7, "roots": [b], "rerun": rerun(&b, "p", 1)}])
    );
}

#[test]
fn a_snapshot_without_its_stint_length_is_flagged() {
    let (one, two) = (build('1'), build('2'));
    for stint in [
        Value::Null,
        json!("600"),
        json!(0),
        json!(crate::assignment::SECONDS_MAX + 1),
        json!(u64::MAX),
    ] {
        let mut older = status('a', "a", &one, 10, 9);
        older["written"] = json!(0);
        let mut newest = status('a', "b", &two, 10, 9);
        newest["stint_seconds"] = stint.clone();
        for only in [None, Some(one.as_str())] {
            let roots = [root(older.clone(), ""), root(newest.clone(), "")];
            let (code, report) = fold(&roots, only, NOW);
            assert_eq!(code, 1, "{stint} {only:?}: {report:#}");
            assert_eq!(
                report["flags"],
                json!([{"root": name('a', "b"), "flag": "missing", "detail": "stint_seconds"}]),
                "{stint} {only:?}"
            );
        }
    }
}

#[test]
fn a_snapshot_ahead_of_the_clock_is_flagged() {
    let one = build('1');
    let mut stale = status('a', "a", &one, 10, 9);
    stale["written"] = json!(0);
    let mut ahead = status('a', "b", &one, 10, 9);
    ahead["written"] = json!(NOW + CLOCK_SKEW_S + 1);
    let (code, report) = fold(&[root(stale.clone(), ""), root(ahead, "")], None, NOW);
    assert_eq!(code, 1, "{report:#}");
    assert_eq!(flags(&report), [on(&name('a', "b"), "missing")]);
    let mut inside = status('a', "b", &one, 10, 9);
    inside["written"] = json!(NOW + CLOCK_SKEW_S);
    let (code, report) = fold(&[root(stale, ""), root(inside, "")], None, NOW);
    assert_eq!((code, flags(&report)), (0, vec![]), "{report:#}");
}

#[test]
fn a_missing_field_prints_unknown_and_adds_nothing() {
    let one = build('1');
    let mut missing = status('a', "a", &one, 100, 90);
    missing["sweep_status"]
        .as_object_mut()
        .expect("an object")
        .remove("runs");
    let (code, report) = fold(&[root(missing, "")], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(report["builds"][&one]["runs"], "unknown");
    assert_eq!(report["roots"][name('a', "a")]["runs"], "unknown");
    assert_eq!(report["builds"][&one]["runs_per_s"], "unknown");
    assert_eq!(
        report["flags"],
        json!([{"root": name('a', "a"), "flag": "missing", "detail": "runs"}])
    );
}

#[test]
fn a_missing_cpu_value_leaves_its_sum_and_the_share_unknown() {
    let one = build('1');
    for field in ["cpu_usec", "capacity_usec"] {
        let mut lacking = status('a', "a", &one, 10, 9);
        lacking.as_object_mut().expect("an object").remove(field);
        let (code, report) = fold(&[root(lacking, "")], None, NOW);
        assert_eq!(code, 1, "{field}");
        assert_eq!(report["builds"][&one][field], "unknown", "{field}");
        assert_eq!(report["builds"][&one]["cpu_share"], "unknown", "{field}");
        assert_eq!(
            report["flags"],
            json!([{"root": name('a', "a"), "flag": "missing", "detail": field}])
        );
    }
}

#[test]
fn a_ratio_with_an_operand_missing_in_one_root_is_unknown() {
    let one = build('1');
    for (field, kept) in [("cpu_usec", 300), ("capacity_usec", 1000)] {
        let mut lacking = status('b', "b", &one, 10, 9);
        lacking.as_object_mut().expect("an object").remove(field);
        let roots = [root(status('a', "a", &one, 10, 9), ""), root(lacking, "")];
        let (_, report) = fold(&roots, None, NOW);
        assert_eq!(report["builds"][&one]["cpu_share"], "unknown", "{field}");
        assert_eq!(report["builds"][&one][field], kept);
    }
    for field in ["runs", "elapsed_s"] {
        let mut lacking = status('b', "b", &one, 10, 9);
        lacking["sweep_status"]
            .as_object_mut()
            .expect("an object")
            .remove(field);
        let roots = [root(status('a', "a", &one, 10, 9), ""), root(lacking, "")];
        let (_, report) = fold(&roots, None, NOW);
        assert_eq!(report["builds"][&one]["runs_per_s"], "unknown", "{field}");
    }
}

#[test]
fn a_build_whose_roots_name_no_host_prints_hosts_unknown() {
    let one = build('1');
    let mut hostless = status('b', "b", &one, 10, 9);
    hostless.as_object_mut().expect("an object").remove("host");
    let roots = [root(status('a', "a", &one, 10, 9), ""), root(hostless, "")];
    let (code, report) = fold(&roots, None, NOW);
    assert_eq!(code, 1);
    assert_eq!(report["builds"][&one]["hosts"], "unknown");
    assert_eq!(report["roots"][name('b', "b")]["host"], "unknown");
    assert_eq!(
        report["flags"],
        json!([{"root": name('b', "b"), "flag": "missing", "detail": "host"}])
    );
}

#[test]
fn a_null_sweep_status_leaves_every_sweep_sum_unknown() {
    let one = build('1');
    let mut null = status('a', "a", &one, 10, 9);
    null["sweep_status"] = Value::Null;
    let (code, report) = fold(&[root(null, "")], None, NOW);
    assert_eq!(code, 1);
    let totals = &report["builds"][&one];
    for field in [
        "runs",
        "uncredited",
        "suspects",
        "replays",
        "missed_controls",
        "missed_histories",
        "elapsed_s",
        "pass",
        "unproven",
        "runs_per_s",
    ] {
        assert_eq!(totals[field], "unknown", "{field}");
    }
    assert_eq!(totals["cpu_share"], 0.3, "the envelope's CPU stays");
    assert_eq!(
        report["flags"],
        json!([{"root": name('a', "a"), "flag": "missing",
                "detail": {"object": "sweep_status", "error": "absent or null"}}])
    );
}

#[test]
fn mistyped_values_print_unknown_and_add_nothing() {
    let one = build('1');
    let mut wrong = status('a', "a", &one, 10, 9);
    wrong["written"] = json!("10000");
    wrong["stint_seconds"] = json!(1.5);
    wrong["sweep_status"]["runs"] = json!(-100);
    wrong["sweep_status"]["pass"] = json!(1.5);
    let roots = [root(wrong, ""), root(status('b', "b", &one, 10, 9), "")];
    let (code, report) = fold(&roots, None, NOW);
    assert_eq!(code, 1, "{report:#}");
    let a = name('a', "a");
    for field in ["written", "stint_seconds", "runs", "pass"] {
        assert_eq!(report["roots"][&a][field], "unknown", "{field}");
    }
    assert_eq!(
        report["flags"],
        json!(
            ["pass", "runs", "stint_seconds", "written"]
                .map(|field| json!({"root": a, "flag": "missing", "detail": field}))
        )
    );
    assert_eq!(report["builds"][&one]["runs"], 10);
    assert_eq!(report["builds"][&one]["pass"], 9);
}

#[test]
fn counts_add_exactly_past_2_53_and_an_overflow_prints_unknown() {
    let one = build('1');
    let mut a = status('a', "a", &one, (1 << 52) + 1, 9);
    a["cpu_usec"] = json!((1u64 << 53) + 1);
    let b = status('b', "b", &one, 1 << 52, 9);
    let (_, report) = fold(&[root(a, ""), root(b, "")], None, NOW);
    assert_eq!(report["builds"][&one]["runs"], (1u64 << 53) + 1);
    assert_eq!(report["builds"][&one]["cpu_usec"], (1u64 << 53) + 301);
    let a = status('a', "a", &one, u64::MAX, 9);
    let b = status('b', "b", &one, 1, 9);
    let (code, report) = fold(&[root(a, ""), root(b, "")], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(report["builds"][&one]["runs"], "unknown");
    assert_eq!(report["builds"][&one]["runs_per_s"], "unknown");
    assert_eq!(
        report["flags"],
        json!([{"root": null, "flag": "missing",
                "detail": {"build": one, "field": "runs", "error": "the build's sum passes 2^64 - 1"}}])
    );
}

#[test]
fn an_alarm_moves_only_its_roots_passes_and_misses_stay_apart() {
    let (one, two) = (build('1'), build('2'));
    let mut alarmed = status('b', "b", &one, 10, 4);
    alarmed["sweep_status"]["alarm"] = json!("1 control runs were missed");
    alarmed["sweep_status"]["histories"]["missed"] = json!(1);
    let mut missing = status('a', "a", &one, 10, 9);
    missing["sweep_status"]["controls"]["missed"] = json!(2);
    let mut alone = status('c', "c", &two, 10, 6);
    alone["sweep_status"]["alarm"] = json!("1 control runs were missed");
    let roots = [root(missing, ""), root(alarmed, ""), root(alone, "")];
    let (code, report) = fold(&roots, None, NOW);
    assert_eq!(code, 2);
    let first = &report["builds"][&one];
    assert_eq!((&first["pass"], &first["unproven"]), (&json!(9), &json!(4)));
    assert_eq!(
        (&first["missed_controls"], &first["missed_histories"]),
        (&json!(2), &json!(1))
    );
    assert_eq!(report["builds"][&two]["pass"], 0, "no unalarmed root");
    assert_eq!(report["builds"][&two]["unproven"], 6);
    assert_eq!(report["roots"][name('b', "b")]["alarmed"], true);
    assert_eq!(
        flags(&report),
        [on(&name('b', "b"), "alarm"), on(&name('c', "c"), "alarm")]
    );
}

#[test]
fn a_kept_text_past_its_bound_is_kept_as_its_length() {
    let one = build('1');
    let a = name('a', "a");
    let mut alarmed = status('a', "a", &one, 10, 9);
    let long = "x".repeat(crate::health::TEXT_MAX + 1);
    alarmed["sweep_status"]["alarm"] = json!(long);
    let listing = json!({"findings": [{"id": long, "held": long, "held_code": "corrupt"}],
                         "release_blockers": []});
    let (_, report) = fold(&[root_with(alarmed, "", listing)], None, NOW);
    let shown = format!("a text of {} bytes", long.len());
    assert_eq!(
        report["flags"][0],
        json!({"root": a, "flag": "alarm", "detail": shown})
    );
    let row = &report["builds"][&one]["findings"][0];
    assert_eq!((&row["id"], &row["held"]), (&json!(shown), &json!(shown)));
    let short = "x".repeat(crate::health::TEXT_MAX);
    assert_eq!(
        kept(&short),
        json!(short),
        "a text at its bound is kept whole"
    );
}

// `campaign` reads the presence of `alarm` or `held` as the verdict. A
// non-text `alarm` counts its root's passes as `unproven`, and a non-text
// `held` keeps its row held.
#[test]
fn an_alarm_or_held_marker_of_another_type_still_marks_its_root_or_row() {
    let one = build('1');
    let a = name('a', "a");
    let mut alarmed = status('a', "a", &one, 10, 9);
    alarmed["sweep_status"]["alarm"] = json!(false);
    let (code, report) = fold(&[root(alarmed, "")], None, NOW);
    assert_eq!(code, 2, "{report:#}");
    let totals = &report["builds"][&one];
    assert_eq!(
        (&totals["pass"], &totals["unproven"]),
        (&json!(0), &json!(9))
    );
    assert_eq!(
        report["flags"],
        json!([{"root": a, "flag": "alarm", "detail": "a value that is not text"}])
    );
    let listing = json!({"findings": [{"id": "f1", "held": 7, "held_code": "corrupt"}],
                         "release_blockers": []});
    let held = root_with(status('a', "a", &one, 10, 9), "", listing);
    let (code, report) = fold(&[held], None, NOW);
    assert_eq!(code, 1, "{report:#}");
    assert_eq!(flags(&report), [on(&a, "held")]);
    assert_eq!(report["builds"][&one]["findings"][0]["held"], "unknown");
}

#[test]
fn a_profile_that_earned_nothing_raises_no_pass_and_exit_2() {
    let one = build('1');
    let mut unpassed = status('a', "a", &one, 100, 40);
    unpassed["sweep_status"]["no_pass"] = json!(["q"]);
    let (code, report) = fold(&[root(unpassed, "")], None, NOW);
    assert_eq!(code, 2);
    assert_eq!(
        report["flags"],
        json!([{"root": name('a', "a"), "flag": "no_pass", "detail": ["q"]}])
    );
    assert_eq!(
        report["builds"][&one]["pass"], 40,
        "the other profiles' passes stay"
    );
    assert_eq!(report["builds"][&one]["unproven"], 0);
    assert_eq!(report["roots"][name('a', "a")]["alarmed"], false);
    for (shape, flagged) in [
        (json!("q"), true),
        (json!({"q": 1}), true),
        (json!([1]), true),
        (json!([]), false),
        (Value::Null, false),
    ] {
        let mut odd = status('a', "a", &one, 100, 40);
        odd["sweep_status"]["no_pass"] = shape.clone();
        let (code, report) = fold(&[root(odd, "")], None, NOW);
        let expected: Vec<(Value, String)> = if flagged {
            vec![on(&name('a', "a"), "missing")]
        } else {
            vec![]
        };
        assert_eq!(flags(&report), expected, "{shape}");
        assert_eq!(code, u8::from(flagged), "{shape}");
    }
}

#[test]
fn an_unreached_event_flags_the_root_and_keeps_its_passes() {
    let one = build('1');
    let base = status('a', "a", &one, 100, 40);
    let listed = |value: Option<Value>| {
        let mut snapshot = base.clone();
        if let Some(value) = value {
            snapshot["sweep_status"]["unreached"] = value;
        }
        fold(&[root(snapshot, "")], None, NOW)
    };
    let (code, report) = listed(Some(
        json!({"p": ["hits", "cross"], "q": [], "r": ["misses"]}),
    ));
    assert_eq!(code, 2);
    assert_eq!(
        report["flags"],
        json!([{"root": name('a', "a"), "flag": "unreached", "detail": [
            {"profile": "p", "events": ["hits", "cross"]}, {"profile": "r", "events": ["misses"]}
        ]}])
    );
    assert_eq!(report["builds"][&one]["pass"], 40);
    let at = "x".repeat(assignment::PROFILE_MAX);
    let long = format!("{at}x");
    let cut = format!("a name of {} bytes", assignment::PROFILE_MAX + 1);
    let (code, report) = listed(Some(json!({long.clone(): [&at, &long]})));
    assert_eq!(code, 2);
    assert_eq!(
        report["flags"],
        json!([{ "root": name('a', "a"), "flag": "unreached",
        "detail": [{"profile": cut, "events": [at, cut]}] }])
    );
    for shape in [
        None,
        Some(Value::Null),
        Some(json!({})),
        Some(json!({"p":[]})),
        Some(Value::Object(
            (0..ELEMENTS).map(|i| (i.to_string(), json!([]))).collect(),
        )),
    ] {
        let (code, report) = listed(shape);
        assert_eq!((code, &report["flags"]), (0, &json!([])));
    }
    for shape in [
        json!([]),
        json!({"p": null}),
        json!({"p": "hits"}),
        json!({"a": ["hits"], "z": [1]}),
        json!({"p": vec!["hits"; ELEMENTS + 1]}),
        Value::Object((0..=ELEMENTS).map(|i| (i.to_string(), json!([]))).collect()),
    ] {
        let (code, report) = listed(Some(shape));
        assert_eq!(code, 1);
        assert_eq!(
            report["flags"],
            json!([{"root": name('a', "a"), "flag": "missing", "detail": {
                "field": "unreached", "error": format!("expected at most {ELEMENTS} distinct profiles mapped to arrays of event names, with at most {ELEMENTS} names per array and in total for this root")
            }}])
        );
    }
}

/// A repeated profile contributes only its last array to its root's budget.
#[test]
fn the_event_budget_counts_effective_arrays_per_root() {
    let build = build('1');
    let full = json!(vec!["hits"; ELEMENTS - 1]);
    let read = |letter, member: &str| {
        let mut envelope = status(letter, "a", &build, 90, 71);
        envelope["sweep_status"]["unreached"] = json!("MEMBER");
        let bytes = envelope
            .to_string()
            .replace("\"MEMBER\"", member)
            .into_bytes();
        let mut root = root(envelope, "");
        root.status = parse(&Object::Read(bytes));
        root
    };
    let keys = (0..ELEMENTS)
        .map(|i| format!(r#""{i}":[]"#))
        .collect::<Vec<_>>()
        .join(",");
    let replaced = read('a', &format!(r#"{{{keys},"0":["hits"]}}"#));
    let (code, report) = fold([&replaced], None, NOW);
    assert_eq!(code, 2);
    assert_eq!(
        report["flags"][0]["detail"],
        json!([{"profile":"0","events":["hits"]}])
    );
    let at = read(
        'a',
        &format!(r#"{{"a":{full},"b":["old","values"],"b":["cross"],"c":[]}}"#),
    );
    let above = read(
        'b',
        &format!(r#"{{"a":{full},"b":[],"b":["cross","hits"]}}"#),
    );
    let sibling = read('c', r#"{"p":["misses"]}"#);
    let (code, report) = fold([&above], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(flags(&report), [on(&name('b', "a"), "missing")]);
    assert_eq!(report["flags"][0]["detail"]["field"], "unreached");
    assert_eq!(report["builds"][&build]["pass"], 71);
    let (code, report) = fold([&at, &above, &sibling], None, NOW);
    assert_eq!(code, 2);
    assert_eq!(report["builds"][&build]["pass"], 213);
    assert_eq!(
        flags(&report),
        [
            on(&name('a', "a"), "unreached"),
            on(&name('c', "a"), "unreached"),
            on(&name('b', "a"), "missing")
        ]
    );
    assert_eq!(
        report["flags"][0]["detail"],
        json!([{"profile":"a","events":full},{"profile":"b","events":["cross"]}])
    );
    assert_eq!(
        report["flags"][1]["detail"],
        json!([{"profile":"p","events":["misses"]}])
    );
}

/// JSON syntax permits a number past the `f64` range, and `serde_json`
/// refuses it when it decodes the value.
#[test]
fn an_unreached_number_past_f64_raises_missing_for_the_field_alone() {
    let one = build('1');
    let a = name('a', "a");
    for member in ["1e400", "-1e400"] {
        let mut envelope = status('a', "a", &one, 100, 40);
        envelope["sweep_status"]["no_pass"] = json!(["q"]);
        envelope["sweep_status"]["unreached"] = json!("MEMBER");
        let bytes = envelope
            .to_string()
            .replace("\"MEMBER\"", member)
            .into_bytes();
        let mut root = root(envelope, "");
        root.status = parse(&Object::Read(bytes));
        let (code, report) = fold([&root], None, NOW);
        assert_eq!(
            flags(&report),
            [on(&a, "no_pass"), on(&a, "missing")],
            "{member}"
        );
        assert_eq!(
            report["flags"][1]["detail"]["field"], "unreached",
            "{member}"
        );
        assert_eq!(code, 2, "{member}");
        assert_eq!(report["builds"][&one]["pass"], 40, "{member}");
    }
}

/// A fresh, stopped host isolates the root's `no_window` flag as the cause
/// of exit code 2.
#[test]
fn a_planned_window_at_zero_flags_the_root_of_a_stopped_host() {
    let one = build('1');
    let a = name('a', "a");
    let mut stopped = record(&host('a'), NOW);
    stopped["phase"] = json!("stopped");
    let listed = |value: Option<Value>| {
        let mut snapshot = status('a', "a", &one, 100, 40);
        if let Some(value) = value {
            snapshot["sweep_status"]["no_window"] = value;
        }
        let records = vec![stored(&host('a'), &stopped, NOW)];
        fold_with(records, &[root(snapshot, "")], None, NOW)
    };
    let cut = "1.accepted-submission.0.after.ProcessDeath";
    let (code, report) = listed(Some(json!({
        "recovery-512": [cut], "recovery-16k": [], "recovery-torn": ["a", "other"],
    })));
    assert_eq!(code, 2, "{report:#}");
    assert_eq!(report["exit"], 2);
    assert_eq!(
        report["flags"],
        json!([{"root": a, "flag": "no_window", "detail": [
            {"profile": "recovery-512", "windows": [cut]},
            {"profile": "recovery-torn", "windows": ["a", "other"]},
        ]}])
    );
    assert_eq!(report["hosts"][host('a')]["state"], "stopped");
    assert_eq!(report["builds"][&one]["pass"], 40);
    assert_eq!(report["builds"][&one]["unproven"], 0);
    assert_eq!(report["roots"][&a]["alarmed"], false);
    let window = "w".repeat(KEY_MAX);
    let longer = format!("{window}w");
    let profile = "p".repeat(assignment::PROFILE_MAX + 1);
    let (code, report) = listed(Some(json!({profile.clone(): [&window, &longer]})));
    assert_eq!(code, 2);
    assert_eq!(
        report["flags"][0]["detail"],
        json!([{
            "profile": format!("a name of {} bytes", profile.len()),
            "windows": [window, format!("a name of {} bytes", longer.len())],
        }])
    );
    for shape in [
        None,
        Some(Value::Null),
        Some(json!({})),
        Some(json!({"p": []})),
    ] {
        let (code, report) = listed(shape);
        assert_eq!((code, &report["flags"]), (0, &json!([])));
    }
    for shape in [
        json!([]),
        json!("w"),
        json!({"p": null}),
        json!({"p": "w"}),
        json!({"a": ["w"], "z": [1]}),
        json!({"p": vec!["w"; ELEMENTS + 1]}),
    ] {
        let (code, report) = listed(Some(shape));
        assert_eq!(code, 1);
        assert_eq!(
            report["flags"],
            json!([{"root": a, "flag": "missing", "detail": {
                "field": "no_window", "error": format!("expected at most {ELEMENTS} distinct profiles mapped to arrays of window names, with at most {ELEMENTS} names per array and in total for this root")
            }}])
        );
    }
}

/// `unreached` and `no_window` each allow up to `ELEMENTS` names per root.
#[test]
fn an_unreached_event_and_a_window_at_zero_flag_one_root_apart() {
    let one = build('1');
    let a = name('a', "a");
    let mut both = status('a', "a", &one, 100, 40);
    both["sweep_status"]["unreached"] = json!({"p": vec!["hits"; ELEMENTS]});
    both["sweep_status"]["no_window"] = json!({"p": vec!["w"; ELEMENTS]});
    let (code, report) = fold(&[root(both, "")], None, NOW);
    assert_eq!(code, 2);
    let mut raised = flags(&report);
    raised.sort_by(|left, right| left.1.cmp(&right.1));
    assert_eq!(raised, [on(&a, "no_window"), on(&a, "unreached")]);
    let first = |flag: &str, member: &str| {
        let entries = report["flags"].as_array().expect("flags");
        let entry = entries.iter().find(|entry| entry["flag"] == flag);
        entry.expect("the flag")["detail"][0][member][0].clone()
    };
    assert_eq!(first("unreached", "events"), "hits");
    assert_eq!(first("no_window", "windows"), "w");
}

#[test]
fn invalid_utf8_in_no_window_refuses_the_whole_status() {
    let mut envelope = status('a', "a", &build('1'), 100, 40);
    envelope["sweep_status"]["no_window"] = json!({"p": ["TOKEN"]});
    let mut bytes = envelope.to_string().into_bytes();
    let token = bytes.windows(5).position(|run| run == b"TOKEN");
    bytes[token.expect("the token")] = 0xff;
    let parsed: Object<Envelope> = parse(&Object::Read(bytes));
    assert!(
        parsed
            .read()
            .is_err_and(|reason| reason.starts_with("does not parse"))
    );
}

#[test]
fn the_other_key_is_judged_against_at_most_eight_listed_lines() {
    let one = build('1');
    let a = name('a', "a");
    let lines = |count: u64| -> String {
        (0..count)
            .map(|run| line(&a, &one, "p", run, "other"))
            .collect()
    };
    let keyless = format!(
        "{}\n",
        json!({"campaign": a, "build": one, "profile": "p", "run": 99, "counts": {"watchdog": 900}, "seed": 7})
    );
    for (counted, list, flagged) in [
        (8, lines(8), false),
        (9, lines(8), true),
        (9, lines(8).repeat(2), true),
        (3, lines(3), false),
        (5, lines(3), true),
        (8, keyless.clone(), false),
        (9, keyless.clone(), true),
    ] {
        let mut overflow = status('a', "a", &one, 10, 9);
        overflow["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"other": counted});
        let (_, report) = fold(&[root(overflow, &list)], None, NOW);
        let others: Vec<(Value, String)> = flags(&report)
            .into_iter()
            .filter(|(_, flag)| flag == "other")
            .collect();
        let expected: Vec<(Value, String)> = if flagged {
            vec![on(&a, "other")]
        } else {
            vec![]
        };
        assert_eq!(others, expected, "{counted}: {report:#}");
    }
}

#[test]
fn a_counted_key_needs_a_line_and_a_listed_key_counts_0_until_counted() {
    let one = build('1');
    let a = name('a', "a");
    let mut unlisted = status('a', "a", &one, 10, 9);
    unlisted["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"k": 1, "z": 0});
    let (code, report) = fold(&[root(unlisted, "")], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(
        report["flags"],
        json!([{"root": a, "flag": "missing",
                "detail": {"profile": "p", "keys": 1, "first": "k",
                           "error": "counted with no listed line"}}])
    );
    let uncounted = status('a', "a", &one, 10, 9);
    let (code, report) = fold(&[root(uncounted, &line(&a, &one, "p", 3, "k"))], None, NOW);
    assert_eq!(code, 0, "{report:#}");
    assert_eq!(report["builds"][&one]["failures"][0]["count"], 0);
    let profileless = status('a', "a", &one, 10, 9);
    let (code, report) = fold(
        &[root(profileless, &line(&a, &one, "q", 3, "k"))],
        None,
        NOW,
    );
    assert_eq!(code, 1);
    assert_eq!(report["builds"][&one]["failures"][0]["count"], "unknown");
    assert_eq!(
        report["flags"],
        json!([{"root": a, "flag": "missing", "detail": "profiles.q.suspect_keys"}])
    );
}

#[test]
fn a_suspect_line_of_another_root_or_of_another_shape_is_never_a_rerun() {
    let one = build('1');
    let a = name('a', "a");
    let mut keyed = status('a', "a", &one, 10, 9);
    keyed["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"k": 3});
    let with = |field: &str, value: Option<Value>| {
        let mut line: Value = serde_json::from_str(&line(&a, &one, "p", 1, "k")).expect("json");
        match value {
            Some(value) => line[field] = value,
            None => {
                line.as_object_mut().expect("an object").remove(field);
            }
        }
        format!("{line}\n")
    };
    let list = [
        with("counts", Some(Value::Null)),
        with("counts", Some(json!({"watchdog": -1}))),
        with("seed", None),
        with("seed", Some(json!("7"))),
        with("profile", Some(json!("p\u{1}"))),
        with(
            "profile",
            Some(json!("p".repeat(crate::assignment::PROFILE_MAX + 1))),
        ),
        with("key", Some(json!("k".repeat(KEY_MAX + 1)))),
        format!("{}\n", json!([a, one, "p", 1, {}, 7, "k"])),
        "not json\n".to_owned(),
        "\n".to_owned(),
        with("campaign", Some(json!(name('z', "z")))),
        with("build", Some(json!(build('2')))),
        line(&a, &one, "p", 9, "k"),
    ]
    .concat();
    let (code, report) = fold(&[root(keyed, &list)], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(report["builds"][&one]["failures"][0]["rerun"]["run"], 9);
    assert_eq!(
        report["flags"],
        json!([
            {"root": a, "flag": "missing",
             "detail": object("suspects.jsonl", "10 lines do not parse as suspect lines")},
            {"root": a, "flag": "missing",
             "detail": object("suspects.jsonl", "2 lines name another campaign, build or counts")},
        ])
    );
}

#[test]
fn a_last_record_without_its_newline_is_flagged_and_is_no_line() {
    let one = build('1');
    let a = name('a', "a");
    let mut keyed = status('a', "a", &one, 10, 9);
    keyed["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"k": 2});
    let list = line(&a, &one, "p", 9, "k") + line(&a, &one, "p", 3, "k").trim_end();
    let (code, report) = fold(&[root(keyed, &list)], None, NOW);
    assert_eq!(code, 1, "{report:#}");
    assert_eq!(report["builds"][&one]["failures"][0]["rerun"]["run"], 9);
    assert_eq!(
        report["flags"],
        json!([{"root": a, "flag": "missing",
                "detail": object("suspects.jsonl", "ends in a record without its newline")}])
    );
}

#[test]
fn many_bad_lines_raise_one_flag() {
    let one = build('1');
    let (code, report) = fold(
        &[root(
            status('a', "a", &one, 10, 9),
            &"\u{1}\n".repeat(10_000),
        )],
        None,
        NOW,
    );
    assert_eq!(code, 1);
    assert_eq!(report["flags"].as_array().expect("flags").len(), 1);
}

#[test]
fn the_bad_keys_of_a_profile_raise_one_flag_with_their_count_and_the_first() {
    let one = build('1');
    let a = name('a', "a");
    let long = "p".repeat(300);
    let keys = |value: Value| -> Value {
        (0..1_000)
            .map(|key| (format!("k{key:04}"), value.clone()))
            .collect::<Map<String, Value>>()
            .into()
    };
    let mut unlisted = status('a', "a", &one, 10, 9);
    unlisted["sweep_status"]["profiles"] = json!({
        long.as_str(): {"suspect_keys": keys(json!(1))},
        "q": {"suspect_keys": keys(json!("1"))},
    });
    let (code, report) = fold(&[root(unlisted, "")], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(
        report["flags"],
        json!([
            {"root": a, "flag": "missing",
             "detail": {"profile": "a name of 300 bytes", "keys": 1_000, "first": "k0000",
                        "error": "counted with no listed line"}},
            {"root": a, "flag": "missing",
             "detail": {"profile": "q", "keys": 1_000, "first": "k0000",
                        "error": "the count is not a whole number"}},
        ])
    );
}

#[test]
fn names_from_a_status_past_their_producers_bounds_show_as_their_length() {
    let one = build('1');
    let a = name('a', "a");
    let profile = "p".repeat(crate::assignment::PROFILE_MAX + 1);
    let key = "k".repeat(KEY_MAX + 1);
    let mut status = status('a', "a", &one, 10, 9);
    status["sweep_status"]["no_pass"] = json!([profile, "q"]);
    status["sweep_status"]["profiles"] = json!({
        profile.as_str(): {},
        "q": {"suspect_keys": {key.as_str(): 1}},
        "r".repeat(crate::assignment::PROFILE_MAX): {},
    });
    let (code, report) = fold(&[root(status, "")], None, NOW);
    assert_eq!(code, 2, "an unpassed profile stays critical: {report:#}");
    let shown_profile = format!("a name of {} bytes", profile.len());
    let at_bound = "r".repeat(crate::assignment::PROFILE_MAX);
    let raised = report["flags"].as_array().expect("flags");
    let expected = [
        json!({"root": a, "flag": "missing",
               "detail": format!("profiles.{shown_profile}.suspect_keys")}),
        json!({"root": a, "flag": "missing",
               "detail": format!("profiles.{at_bound}.suspect_keys")}),
        json!({"root": a, "flag": "missing",
               "detail": {"profile": "q", "keys": 1,
                          "first": format!("a name of {} bytes", key.len()),
                          "error": "counted with no listed line"}}),
        json!({"root": a, "flag": "no_pass", "detail": [shown_profile, "q"]}),
    ];
    assert_eq!(raised.len(), expected.len(), "{raised:#?}");
    for flag in &expected {
        assert!(raised.contains(flag), "{flag} in {raised:#?}");
    }
}

#[test]
fn counts_whose_names_pass_the_argument_budget_are_mistyped() {
    let one = build('1');
    let mut status = status('a', "a", &one, 10, 9);
    let width = crate::assignment::ARGUMENT_MAX;
    let names = crate::assignment::ARGUMENTS_MAX / width + 1;
    let counts: Map<String, Value> = (0..names)
        .map(|index| (format!("{index:08}{}", "n".repeat(width - 8)), json!(1)))
        .collect();
    status["sweep_status"]["counts"] = counts.into();
    let (_, report) = fold(&[root(status, "")], None, NOW);
    assert!(
        flags(&report).contains(&on(&name('a', "a"), "missing")),
        "{report:#}"
    );
    assert_eq!(report["flags"][0]["detail"], json!("counts"), "{report:#}");
}

#[test]
fn keyless_lines_stay_unkeyed_and_keep_their_reruns() {
    let one = build('1');
    let a = name('a', "a");
    let mut old = status('a', "a", &one, 10, 9);
    old["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"violation: x": 2, "other": 3});
    let keyless = |run: u64| {
        format!(
            "{}\n",
            json!({"campaign": a, "build": one, "profile": "p", "run": run, "counts": {"watchdog": 900}, "seed": 7})
        )
    };
    let (code, report) = fold(&[root(old, &(keyless(4) + &keyless(2)))], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(
        report["builds"][&one]["unkeyed"],
        json!([
            {"campaign": a, "profile": "p", "run": 2, "counts": {"watchdog": 900}},
            {"campaign": a, "profile": "p", "run": 4, "counts": {"watchdog": 900}},
        ])
    );
    assert_eq!(report["builds"][&one]["failures"], json!([]));
    assert_eq!(
        report["flags"],
        json!([{"root": a, "flag": "missing",
                "detail": object("suspects.jsonl", "2 lines carry no key")}])
    );
}

// A typed member prints where a `Value` object would print it, and the
// reruns of one root print one copy of its counts.
#[test]
fn the_document_prints_in_name_order_from_one_copy_of_each_roots_counts() {
    let (one, two) = (build('1'), build('2'));
    let (a, b) = (name('a', "a"), name('b', "b"));
    let keyless = format!(
        "{}\n",
        json!({"campaign": a, "build": one, "profile": "p", "run": 2,
               "counts": {"watchdog": 900}, "seed": 7})
    );
    let mut first = status('a', "a", &one, 10, 9);
    first["sweep_status"]["alarm"] = json!("1 control runs were missed");
    let findings = json!({"findings": [{"id": "f1", "resolved": false, "dispositions": []}],
                          "release_blockers": []});
    let list = line(&a, &one, "p", 4, "k") + &line(&a, &one, "q", 5, "j") + &keyless;
    let roots = [
        root_with(first, &list, findings),
        root(status('b', "b", &two, 10, 9), &line(&b, &two, "p", 1, "k")),
    ];
    let mut report = Report::new(None, NOW);
    roots.iter().for_each(|root| report.add(root));
    let (_, document) = report.finish(Vec::new());
    let printed = serde_json::to_string_pretty(&document).expect("the document prints");
    let value = serde_json::to_value(&document).expect("the document serializes");
    assert_eq!(printed, format!("{value:#}"));
    let members = &document.builds[&one];
    let (Member::Failures(failures), Member::Unkeyed(unkeyed)) =
        (&members["failures"], &members["unkeyed"])
    else {
        panic!("the lists are typed members");
    };
    let copies: Vec<&Rc<Counts>> = failures
        .iter()
        .filter_map(|group| group.rerun.as_ref())
        .chain(unkeyed)
        .map(|rerun| &rerun.counts)
        .collect();
    assert_eq!(copies.len(), 3);
    assert!(copies.iter().all(|copy| Rc::ptr_eq(copy, copies[0])));
}

#[test]
fn a_line_with_other_counts_than_its_root_is_never_a_rerun() {
    let one = build('1');
    let (a, b) = (name('a', "a"), name('b', "b"));
    let with = |campaign: &str, run: u64, counts: Value, key: Option<&str>| {
        let mut line = json!({"campaign": campaign, "build": one, "profile": "p", "run": run,
                              "counts": counts, "seed": 7});
        if let Some(key) = key {
            line["key"] = json!(key);
        }
        format!("{line}\n")
    };
    let mut first = status('a', "a", &one, 10, 9);
    first["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"k": 2});
    let mut second = status('b', "b", &one, 10, 9);
    second["sweep_status"]["counts"] = json!({"watchdog": 5});
    second["sweep_status"]["profiles"]["p"]["suspect_keys"] = json!({"k": 1});
    let roots = [
        root(
            first,
            &(with(&a, 1, json!({"watchdog": 901}), Some("k"))
                + &with(&a, 9, json!({"watchdog": 900}), Some("k"))),
        ),
        root(
            second,
            &(with(&b, 0, json!({"watchdog": 5}), Some("k"))
                + &with(&b, 3, json!({"watchdog": 5}), None)
                + &with(&b, 2, json!({}), None)),
        ),
    ];
    let (code, report) = fold(&roots, None, NOW);
    assert_eq!(code, 1, "{report:#}");
    let totals = &report["builds"][&one];
    assert_eq!(
        totals["failures"],
        json!([{"profile": "p", "key": "k", "count": 3, "roots": [a, b],
                "rerun": {"campaign": a, "profile": "p", "run": 9, "counts": {"watchdog": 900}}}])
    );
    assert_eq!(
        totals["unkeyed"],
        json!([{"campaign": b, "profile": "p", "run": 3, "counts": {"watchdog": 5}}])
    );
    let foreign = object(
        "suspects.jsonl",
        "1 lines name another campaign, build or counts",
    );
    assert_eq!(
        report["flags"],
        json!([
            {"root": b, "flag": "missing",
             "detail": object("suspects.jsonl", "1 lines carry no key")},
            {"root": a, "flag": "missing", "detail": foreign},
            {"root": b, "flag": "missing", "detail": foreign},
        ])
    );
}

#[test]
fn a_line_whose_counts_pass_the_element_bound_is_unreadable() {
    let one = build('1');
    let a = name('a', "a");
    let counts: Map<String, Value> = (0..=ELEMENTS)
        .map(|key| (format!("k{key}"), json!(0)))
        .collect();
    let list = format!(
        "{}\n",
        json!({"campaign": a, "build": one, "profile": "p", "run": 1, "counts": counts, "seed": 7})
    );
    let (code, report) = fold(&[root(status('a', "a", &one, 10, 9), &list)], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(report["builds"][&one]["unkeyed"], json!([]));
    assert_eq!(
        report["flags"],
        json!([{"root": a, "flag": "missing",
                "detail": object("suspects.jsonl", "1 lines do not parse as suspect lines")}])
    );
}

#[test]
fn a_root_lists_at_most_the_element_bound_of_keys_and_of_keyless_lines() {
    let one = build('1');
    let (a, b) = (name('a', "a"), name('b', "b"));
    let keyless = |run: usize| {
        format!(
            "{}\n",
            json!({"campaign": a, "build": one, "profile": "p", "run": run,
                   "counts": {"watchdog": 900}, "seed": 7})
        )
    };
    let mut list = String::new();
    for index in 0..=ELEMENTS {
        list += &line(&a, &one, "p", 5, &format!("k{index:05}"));
        list += &keyless(index);
    }
    // A line of a listed key past the bound still lowers that key's rerun,
    // and a keyless line listed twice takes one place.
    list += &line(&a, &one, "p", 1, "k00000");
    list += &keyless(0);
    let roots = [
        root(status('a', "a", &one, 10, 9), &list),
        root(
            status('b', "b", &one, 10, 9),
            &line(&b, &one, "p", 0, &format!("k{ELEMENTS:05}")),
        ),
    ];
    let (code, report) = fold(&roots, None, NOW);
    assert_eq!(code, 1);
    let totals = &report["builds"][&one];
    let failures = totals["failures"].as_array().expect("failures");
    assert_eq!(
        failures.len(),
        ELEMENTS + 1,
        "the keys of a and the key of b"
    );
    assert_eq!(failures[0]["rerun"]["run"], 1);
    assert_eq!(failures[ELEMENTS]["roots"], json!([b]));
    assert_eq!(
        totals["unkeyed"].as_array().expect("unkeyed").len(),
        ELEMENTS
    );
    let past =
        format!("2 lines pass the {ELEMENTS} keys or the {ELEMENTS} keyless lines one root lists");
    assert!(
        report["flags"]
            .as_array()
            .expect("flags")
            .contains(&json!({"root": a, "flag": "missing",
                              "detail": object("suspects.jsonl", &past)})),
        "{}",
        report["flags"]
    );
    let reversed = fold(roots.iter().rev(), None, NOW).1;
    assert_eq!(reversed, report, "the bound is per root under either order");
}

#[test]
fn a_status_without_counts_lists_none_of_its_lines() {
    let one = build('1');
    let a = name('a', "a");
    let long: Map<String, Value> = (0..=ELEMENTS)
        .map(|key| (format!("k{key}"), json!(0)))
        .collect();
    for counts in [
        None,
        Some(Value::Null),
        Some(json!("watchdog=900")),
        Some(json!({"watchdog": 1.5})),
        Some(json!({"watch\u{1}dog": 900})),
        Some(Value::Object(long)),
    ] {
        let mut bare = status('a', "a", &one, 10, 9);
        let swept = bare["sweep_status"].as_object_mut().expect("an object");
        match &counts {
            Some(counts) => swept.insert("counts".into(), counts.clone()),
            None => swept.remove("counts"),
        };
        let list = line(&a, &one, "p", 1, "k");
        let (code, report) = fold(&[root(bare, &list)], None, NOW);
        assert_eq!(code, 1, "{counts:?}");
        let totals = &report["builds"][&one];
        assert_eq!(totals["failures"], json!([]), "{counts:?}");
        assert_eq!(totals["runs"], 10, "the sums stay");
        assert_eq!(
            report["flags"],
            json!([{"root": a, "flag": "missing", "detail": "counts"}])
        );
    }
}

#[test]
fn an_envelope_that_contradicts_its_root_adds_nothing() {
    let one = build('1');
    let a = name('a', "a");
    for (path, value) in [
        (&["format"][..], json!(2)),
        (&["format"][..], Value::Null),
        (&["campaign"][..], json!(name('z', "z"))),
        (&["build"][..], json!("b1")),
        (&["host"][..], json!(host('b'))),
        (&["host"][..], json!("host-a")),
        (&["sweep_status", "campaign"][..], json!(name('z', "z"))),
        (&["sweep_status", "campaign"][..], json!(7)),
        (&["sweep_status", "campaign"][..], Value::Null),
        (&["sweep_status"][..], json!([1])),
    ] {
        let mut refused = status('a', "a", &one, 10, 9);
        match path {
            [field] => refused[*field] = value.clone(),
            [outer, inner] => refused[*outer][*inner] = value.clone(),
            _ => unreachable!("each path names one or two fields"),
        }
        let mut refused = root(refused, "");
        refused.campaign = a.clone();
        let (code, report) = fold([&refused], None, NOW);
        assert_eq!(code, 1, "{path:?}");
        assert_eq!(report["builds"], json!({}), "{path:?}");
        assert_eq!(flags(&report), [on(&a, "missing")], "{path:?}");
        assert_eq!(report["flags"][0]["detail"]["object"], "status.json");
    }
    let mut unnamed = status('a', "a", &one, 10, 9);
    unnamed["sweep_status"]
        .as_object_mut()
        .expect("an object")
        .remove("campaign");
    let (code, report) = fold(&[root(unnamed, "")], None, NOW);
    assert_eq!(code, 1, "a sweep_status without a campaign");
    assert_eq!(report["builds"], json!({}));
    assert_eq!(flags(&report), [on(&a, "missing")]);
}

#[test]
fn a_root_naming_another_host_gives_that_host_no_snapshot() {
    let one = build('1');
    let mut stale = status('a', "a", &one, 10, 9);
    stale["written"] = json!(0);
    let mut forged = status('b', "b", &one, 10, 9);
    forged["host"] = json!(host('a'));
    let roots = [root(stale, ""), root(forged, "")];
    let (code, report) = fold_with(Vec::new(), &roots, None, NOW);
    assert_eq!(code, 1);
    assert_eq!(flags(&report), [on(&name('b', "b"), "missing")]);
    assert_eq!(report["hosts"], json!({}), "host a's own snapshot is stale");
    assert_eq!(report["builds"][&one]["roots"], 1);
}

#[test]
fn findings_print_their_latest_decision_and_flag_held_or_partial_rows() {
    let one = build('1');
    let a = name('a', "a");
    let listing = json!({"findings": [
        {"id": "f1", "resolved": true,
         "dispositions": [{"decision": "harness"}, {"decision": "resolved"}]},
        {"id": "f2", "resolved": false, "dispositions": []},
    ], "release_blockers": []});
    let (code, report) = fold(
        &[root_with(status('a', "a", &one, 10, 9), "", listing)],
        None,
        NOW,
    );
    assert_eq!(code, 0, "{report:#}");
    let findings = &report["builds"][&one]["findings"];
    assert_eq!(findings[0]["disposition"], "resolved");
    assert_eq!(findings[1]["disposition"], Value::Null);
    for (row, kind, field, printed) in [
        (
            json!({"id": "f3", "held": "the record does not parse", "held_code": "corrupt",
                   "blocker": true}),
            "held",
            "held_code",
            json!("corrupt"),
        ),
        (
            json!({"id": "f4", "dispositions": []}),
            "missing",
            "resolved",
            json!("unknown"),
        ),
        (
            json!({"id": 4, "resolved": true, "dispositions": []}),
            "missing",
            "id",
            json!("unknown"),
        ),
        (
            json!({"id": "f5", "resolved": true, "dispositions": [{"decision": 3}]}),
            "missing",
            "disposition",
            json!("unknown"),
        ),
        (
            json!({"id": "f6", "resolved": true, "dispositions": ["resolved"]}),
            "missing",
            "disposition",
            json!("unknown"),
        ),
    ] {
        let listing = json!({"findings": [row], "release_blockers": []});
        let (code, report) = fold(
            &[root_with(status('a', "a", &one, 10, 9), "", listing)],
            None,
            NOW,
        );
        assert_eq!(code, 1, "{row}");
        assert_eq!(
            report["builds"][&one]["findings"][0][field], printed,
            "{row}"
        );
        assert_eq!(flags(&report), [on(&a, kind)], "{row}");
    }
    let listing = json!({"release_blockers": []});
    let (_, report) = fold(
        &[root_with(status('a', "a", &one, 10, 9), "", listing)],
        None,
        NOW,
    );
    assert_eq!(
        report["flags"][0]["detail"],
        object("findings.json", "holds no array of at most 65536 findings")
    );
}

#[test]
fn a_findings_array_past_the_element_bound_lists_no_row_and_flags_its_root() {
    let one = build('1');
    let listing = |rows: usize| {
        let row = json!({"id": "f", "resolved": true, "dispositions": []});
        json!({"findings": vec![row; rows], "release_blockers": []})
    };
    let fold_rows = |rows: usize| {
        let root = root_with(status('a', "a", &one, 10, 9), "", listing(rows));
        fold([&root], None, NOW)
    };
    let (code, report) = fold_rows(ELEMENTS);
    assert_eq!(code, 0);
    assert_eq!(
        report["builds"][&one]["findings"].as_array().map(Vec::len),
        Some(ELEMENTS)
    );
    let (code, report) = fold_rows(ELEMENTS + 1);
    assert_eq!(code, 1);
    assert_eq!(report["builds"][&one]["findings"], json!([]));
    assert_eq!(
        report["flags"],
        json!([{"root": name('a', "a"), "flag": "missing",
                "detail": object("findings.json", "holds no array of at most 65536 findings")}])
    );
}

#[test]
fn an_absent_or_unreadable_object_flags_its_root() {
    let one = build('1');
    let a = name('a', "a");
    let mut absent = root(status('a', "a", &one, 10, 9), "");
    absent.payload = Some(Payload {
        suspects: Object::Absent,
        findings: Object::Unreadable("does not parse: EOF".into()),
    });
    let (code, report) = fold([&absent], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(
        report["flags"],
        json!([
            {"root": a, "flag": "missing", "detail": object("suspects.jsonl", "absent")},
            {"root": a, "flag": "missing", "detail": object("findings.json", "does not parse: EOF")},
        ])
    );
    absent.status = Object::Absent;
    for only in [None, Some(one.as_str())] {
        let (_, report) = fold([&absent], only, NOW);
        let details: Vec<&Value> = report["flags"]
            .as_array()
            .expect("flags")
            .iter()
            .filter(|flag| flag["root"] == json!(a))
            .map(|flag| &flag["detail"])
            .collect();
        assert_eq!(
            details,
            [&object("status.json", "absent")],
            "{only:?}: {report:#}"
        );
    }
}

#[test]
fn a_build_filter_that_matches_no_root_is_flagged_without_a_root() {
    let (one, two) = (build('1'), build('2'));
    let (code, report) = fold(&[root(status('a', "a", &one, 10, 9), "")], Some(&two), NOW);
    assert_eq!(code, 1);
    assert_eq!(report["builds"], json!({}));
    assert!(report["flags"][0]["root"].is_null());
    assert_eq!(
        report["flags"],
        json!([{"root": null, "flag": "missing",
                "detail": {"build": two, "error": "no root names the build"}}])
    );
}

#[test]
fn each_host_state_sets_its_flag_and_exit_code() {
    let one = build('1');
    let a = host('a');
    let roots = [root(status('a', "a", &one, 10, 9), "")];
    let mut stopped = record(&a, NOW);
    stopped["phase"] = json!("stopped");
    let mut degraded = record(&a, NOW);
    degraded["upload_error"] = json!("refused");
    let mut blocked = record(&a, NOW);
    blocked["phase"] = json!("blocked");
    let cases = [
        (record(&a, NOW), 0, None, "active"),
        (stopped, 0, None, "stopped"),
        (degraded, 1, Some("degraded"), "degraded"),
        (blocked, 2, Some("unhealthy"), "unhealthy"),
        (record(&a, NOW - 7_201), 2, Some("silent"), "silent"),
        (
            json!({"instance": host('b')}),
            1,
            Some("missing"),
            "missing",
        ),
    ];
    for (record, code, flag, state) in cases {
        let (exit, report) = fold_with(vec![stored(&a, &record, NOW)], &roots, None, NOW);
        assert_eq!(exit, code, "{state}: {report:#}");
        assert_eq!(report["exit"], code);
        let raised: Vec<(Value, String)> = flag
            .into_iter()
            .map(|flag| (Value::Null, flag.to_owned()))
            .collect();
        assert_eq!(flags(&report), raised, "{state}");
        assert_eq!(report["hosts"][&a]["state"], state);
        let mut counts = json!({
            "active": 0, "degraded": 0, "missing": 0, "silent": 0, "stopped": 0, "unhealthy": 0,
        });
        counts[state] = json!(1);
        assert_eq!(report["host_counts"], counts, "{state}");
        if let Some(flag) = flag {
            assert_eq!(report["flags"][0]["detail"]["host"], a.as_str(), "{flag}");
        }
    }
    let unnamed = Record::Unnamed {
        key: "hosts/not-an-id/health.json".into(),
    };
    let (code, report) = fold_with(vec![unnamed], &[], None, NOW);
    assert_eq!(code, 1);
    assert_eq!(report["hosts"], json!({}));
    assert_eq!(
        report["flags"],
        json!([{"root": null, "flag": "missing", "detail":
            {"key": "hosts/not-an-id/health.json", "error": "its instance part is no instance id"}}])
    );
}

#[test]
fn the_host_section_is_the_same_under_any_listing_order_and_any_build() {
    let (one, two) = (build('1'), build('2'));
    let mut stale_blocked = record(&host('c'), NOW - 7_201);
    stale_blocked["phase"] = json!("blocked");
    let records = vec![
        stored(&host('a'), &record(&host('a'), NOW), NOW),
        stored(&host('b'), &record(&host('b'), NOW - 7_201), NOW),
        stored(&host('c'), &stale_blocked, NOW),
        Record::Unnamed {
            key: "hosts/x/health.json".into(),
        },
    ];
    let mut retired = status('e', "e9", &two, 10, 9);
    retired["written"] = json!(NOW - 7_201);
    let roots = [
        root(status('a', "a", &one, 10, 9), ""),
        root(status('b', "b", &two, 10, 9), ""),
        root(status('d', "d", &two, 10, 9), ""),
        root(retired, ""),
        root(status('e', "e2", &one, 10, 9), ""),
    ];
    let forward = fold_with(records.clone(), &roots, None, NOW);
    let reversed: Vec<Record> = records.iter().rev().cloned().collect();
    let backward = fold_with(reversed, roots.iter().rev(), None, NOW);
    assert_eq!(forward.1.to_string(), backward.1.to_string());
    assert_eq!(forward.0, 2);
    let section = |report: &Value| {
        let host_flags: Vec<Value> = report["flags"]
            .as_array()
            .expect("flags")
            .iter()
            .filter(|flag| flag["root"].is_null() && flag["detail"]["build"].is_null())
            .cloned()
            .collect();
        (
            report["hosts"].clone(),
            report["host_counts"].clone(),
            host_flags,
        )
    };
    let expected = section(&forward.1);
    assert_eq!(
        expected
            .0
            .as_object()
            .expect("rows")
            .keys()
            .collect::<Vec<_>>(),
        [&host('a'), &host('b'), &host('c'), &host('d'), &host('e')]
    );
    assert_eq!(expected.0[host('b')]["state"], "silent");
    assert_eq!(expected.0[host('c')]["state"], "silent");
    assert_eq!(expected.0[host('d')]["state"], "missing");
    assert_eq!(expected.0[host('e')]["state"], "missing");
    for only in [Some(one.as_str()), Some(two.as_str()), Some(&*build('3'))] {
        let (code, report) = fold_with(records.clone(), &roots, only, NOW);
        assert_eq!(section(&report), expected, "{only:?}");
        assert_eq!(code, 2, "no --build hides a silent host: {only:?}");
    }
}

/// A host with no record is judged by its newest snapshot alone: the
/// greatest `written` within the skew of its root's clock, then the
/// greatest campaign name, in either listing order and under any build.
#[test]
fn a_recordless_host_is_judged_by_its_newest_snapshot_alone() {
    let (one, two) = (build('1'), build('2'));
    let snapshot = |nonce: &str, build: &str, written: u64, stint: Value| {
        let mut status = status('a', nonce, build, 10, 9);
        status["written"] = json!(written);
        status["stint_seconds"] = stint;
        status
    };
    let stale = snapshot("a", &one, NOW - 7_201, json!(3600));
    let cases = [
        (
            "a stale and a fresh snapshot",
            [stale.clone(), snapshot("b", &two, NOW - 100, json!(3600))],
            true,
        ),
        (
            "a stale snapshot and one past the skew",
            [
                stale.clone(),
                snapshot("c", &two, NOW + CLOCK_SKEW_S + 1, json!(3600)),
            ],
            false,
        ),
        (
            "a fresh snapshot under the lesser campaign name",
            [
                snapshot("z", &one, NOW - 7_201, json!(3600)),
                snapshot("b", &two, NOW - 100, json!(3600)),
            ],
            true,
        ),
        (
            "a fresh snapshot of the longest stint length",
            [
                stale.clone(),
                snapshot("b", &two, NOW - 100, json!(crate::assignment::SECONDS_MAX)),
            ],
            true,
        ),
        (
            "a tie on written that the greater campaign's stale stint wins",
            [
                snapshot("d", &one, NOW - 100, json!(3600)),
                snapshot("e", &two, NOW - 100, json!(10)),
            ],
            false,
        ),
        (
            "a newest snapshot with no stint length",
            [
                snapshot("f", &one, NOW - 200, json!(3600)),
                snapshot("g", &two, NOW - 100, Value::Null),
            ],
            false,
        ),
    ];
    for (name, statuses, missing) in cases {
        for reversed in [false, true] {
            let mut ordered = statuses.clone();
            if reversed {
                ordered.reverse();
            }
            let roots: Vec<Root> = ordered.into_iter().map(|status| root(status, "")).collect();
            for only in [
                None,
                Some(one.as_str()),
                Some(two.as_str()),
                Some(&*build('3')),
            ] {
                let (_, report) = fold_with(Vec::new(), &roots, only, NOW);
                let rows = report["hosts"].as_object().expect("rows");
                if missing {
                    assert_eq!(rows.len(), 1, "{name} {only:?}: {report:#}");
                    assert_eq!(rows[&host('a')]["state"], "missing", "{name} {only:?}");
                    let host_flags: Vec<&Value> = report["flags"]
                        .as_array()
                        .expect("flags")
                        .iter()
                        .filter(|flag| flag["detail"]["host"] == host('a').as_str())
                        .collect();
                    assert_eq!(host_flags.len(), 1, "{name} {only:?}: {report:#}");
                    assert!(
                        !report["flags"].to_string().contains("\"stint_seconds\""),
                        "{name}: {report:#}"
                    );
                } else {
                    assert!(rows.is_empty(), "{name} {reversed} {only:?}: {report:#}");
                }
            }
        }
    }
    let ahead = root(snapshot("c", &two, NOW + CLOCK_SKEW_S + 1, json!(3600)), "");
    let (_, report) = fold_with(Vec::new(), [&root(stale, ""), &ahead], None, NOW);
    assert!(
        flags(&report).contains(&on(&name('a', "c"), "missing")),
        "the snapshot past the skew flags its own root: {report:#}"
    );
}

#[test]
fn a_stale_snapshot_beside_a_fresh_record_raises_no_silent() {
    let one = build('1');
    let mut stale = status('a', "a", &one, 10, 9);
    stale["written"] = json!(0);
    let (code, report) = fold(&[root(stale, "")], None, NOW);
    assert_eq!((code, flags(&report)), (0, vec![]), "{report:#}");
    assert_eq!(report["hosts"][host('a')]["state"], "active");
}

// The decision step reads the failure groups from the typed document and
// every other member from the view. The view holds `hosts`, `host_counts`
// and `flags` as the document prints them and each build's totals alone;
// the per-root rows stay in the document. Each lent group serializes to
// the object the document prints for it.
#[test]
fn the_decision_view_holds_the_totals_and_the_document_lends_its_failure_groups() {
    let (one, two) = (build('1'), build('2'));
    let (a, b) = (name('a', "a"), name('b', "b"));
    let mut first = status('a', "a", &one, 10, 9);
    first["sweep_status"]["profiles"] = json!({"p": {"suspect_keys": {"k": 3, "j": 1}}});
    let list = [line(&a, &one, "p", 50, "k"), line(&a, &one, "p", 60, "j")].concat();
    let mut second = status('b', "b", &two, 10, 9);
    second["sweep_status"]["profiles"] = json!({"p": {"suspect_keys": {"k": 2}}});
    let roots = [
        root(second, &line(&b, &two, "p", 70, "k")),
        root(first, &list),
    ];
    let hosts = vec![stored(&host('a'), &record(&host('a'), NOW), NOW)];
    let mut report = Report::new(None, NOW);
    for root in &roots {
        report.add(root);
    }
    let (_, document) = report.finish(hosts);
    let full = serde_json::to_value(&document).expect("the document serializes");
    let view = document.decision_view();
    let lent: Vec<(&str, &str, &str, Value)> = document
        .failures()
        .map(|(build, group)| {
            let printed = serde_json::to_value(group).expect("the group serializes");
            (build, group.profile.as_str(), group.key.as_str(), printed)
        })
        .collect();
    assert_eq!(
        lent,
        [
            (
                one.as_str(),
                "p",
                "j",
                full["builds"][&one]["failures"][0].clone()
            ),
            (
                one.as_str(),
                "p",
                "k",
                full["builds"][&one]["failures"][1].clone()
            ),
            (
                two.as_str(),
                "p",
                "k",
                full["builds"][&two]["failures"][0].clone()
            ),
        ],
        "every group of every build, builds in id order, as the document prints it"
    );
    assert_eq!(lent[1].3["rerun"]["counts"], json!({"watchdog": 900}));
    for member in ["hosts", "host_counts", "flags"] {
        assert_eq!(view[member], full[member], "{member}");
    }
    let totals = |entry: &Value| -> Value {
        entry
            .as_object()
            .expect("a build")
            .iter()
            .filter(|(name, _)| ![FAILURES, FINDINGS, UNKEYED].contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Map<String, Value>>()
            .into()
    };
    for build in [&one, &two] {
        assert_eq!(
            view["builds"][build],
            totals(&full["builds"][build]),
            "every total of the build and none of its lists"
        );
        assert!(totals(&full["builds"][build])["runs"].is_number());
    }
    assert!(
        view.get("roots").is_none(),
        "the per-root rows are left out"
    );
}
