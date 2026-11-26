use super::{Kept, SOURCE, Sweep, probes};
use crate::campaign::state_fixture::{finished_probe, probe, released_probe};
use crate::record::{Digest, ProbeOutcome};
use crate::step::{Outcome, Step};
use crate::store::Store;
use crate::store::fixture::{Case, Snapshot, bounded, observed, scripted, snapshot};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// A cgroup path that is absent, as a released probe leaves it, equal in
/// every case so trees from separate cases compare byte for byte.
const GONE: &str = "/sys/fs/cgroup/campaign-released-probe";

/// The reason for keeping a removable verified listing source.
const LISTING_SOURCE: &str = "probe holds a verified listing source for its build";

/// Runs the sweep from a fresh store handle.
fn sweep(case: &Case) -> Sweep {
    let store = Store::open(&case.state).unwrap();
    probes(&store, false, usize::MAX, &mut || false).unwrap()
}

/// Each kept probe with its reason.
fn reasons(swept: &Sweep) -> BTreeMap<&str, &str> {
    swept
        .kept
        .iter()
        .map(|kept| (kept.probe.as_str(), kept.reason.as_str()))
        .collect()
}

/// `tree` without the probe directories `removed`.
fn without(mut tree: Snapshot, removed: &[&str]) -> Snapshot {
    tree.retain(|path, _| {
        !removed
            .iter()
            .any(|probe| path.starts_with(Path::new("probes").join(probe)))
    });
    tree
}

/// A finished, released probe and an empty probe directory are removed,
/// except the last completed probe of the build, whose listing the report
/// reads. A reserved probe and an unfinished probe keep every entry and are
/// reported. A corpus probe is left alone.
#[test]
fn collect_removes_released_probes_and_keeps_held_ones() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    released_probe(&store, "probe-earlier", GONE);
    released_probe(&store, "probe-released", GONE);
    probe(&store, "probe-empty", 0);
    let reserved = released_probe(&store, "probe-reserved", GONE);
    store
        .create_once(&reserved, &crate::campaign::name("reservation"), b"{}")
        .unwrap();
    let unfinished = released_probe(&store, "probe-unfinished", GONE);
    store
        .delete(&unfinished, &crate::campaign::name("finished"))
        .unwrap();
    released_probe(&store, "corpus-probe-1", GONE);
    let expected = without(snapshot(&case.state), &["probe-earlier", "probe-empty"]);
    let swept = probes(&store, false, usize::MAX, &mut || false).unwrap();
    assert_eq!(swept.removed, ["probe-earlier", "probe-empty"]);
    assert_eq!(
        reasons(&swept),
        BTreeMap::from([
            ("probe-released", LISTING_SOURCE),
            ("probe-reserved", "probe holds a reservation"),
            ("probe-unfinished", "probe has no finished record"),
        ])
    );
    assert_eq!(swept.kept[0].code, SOURCE);
    assert_eq!(swept.kept[1].code, "binding");
    assert_eq!(snapshot(&case.state), expected);
}

/// Each build keeps the last probe, by name, whose listing verifies, and
/// redundant finished probes with intact evidence are removed. A probe
/// whose listing differs from its artifact record is preserved, while a
/// released probe with a held outcome and intact evidence is removed. The report declares the same profiles before and after.
#[test]
fn each_build_keeps_its_verified_listing_and_other_probes_are_removed() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let one = Digest::of(b"one");
    let two = Digest::of(b"two");
    for (probe, build, outcome) in [
        ("probe-a", one, ProbeOutcome::Complete),
        ("probe-b", two, ProbeOutcome::Complete),
        ("probe-y", one, ProbeOutcome::Complete),
        ("probe-z", two, ProbeOutcome::Held),
    ] {
        finished_probe(&store, probe, GONE, build, outcome);
    }
    drop(store);
    fs::write(
        case.state
            .join("probes/probe-y/artifacts/probe/capabilities.stdout"),
        b"damaged listing",
    )
    .unwrap();
    let profiles = crate::campaign::report(&case.state).unwrap()["profiles"].clone();
    let expected = without(snapshot(&case.state), &["probe-z"]);
    let swept = sweep(&case);
    assert_eq!(swept.removed, ["probe-z"]);
    assert_eq!(
        reasons(&swept),
        BTreeMap::from([
            ("probe-a", LISTING_SOURCE),
            ("probe-b", LISTING_SOURCE),
            ("probe-y", "probe stream capabilities.stdout digest differs"),
        ])
    );
    assert_eq!(snapshot(&case.state), expected);
    assert_eq!(
        crate::campaign::report(&case.state).unwrap()["profiles"],
        profiles
    );
}

/// The two-probe tree of the kill tests: `probe-a` and the empty
/// `probe-b` are removed, and `probe-z` is the build's listing source.
fn kill_tree() -> Case {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    released_probe(&store, "probe-a", GONE);
    probe(&store, "probe-b", 0);
    released_probe(&store, "probe-z", GONE);
    drop(store);
    case
}

/// The indices of the steps of `trace` that are `steps`.
fn points(trace: &[Step], steps: &[Step]) -> Vec<usize> {
    trace
        .iter()
        .enumerate()
        .filter(|(_, step)| steps.contains(step))
        .map(|(index, _)| index)
        .collect()
}

/// Kills a sweep of `case` at step `point`, requiring the killed run to
/// have followed `reference` up to the kill.
fn killed(case: &Case, point: usize, reference: &[Step]) {
    let store = Store::open(&case.state).unwrap();
    let (result, trace) = scripted([(point, Outcome::Kill)], || {
        probes(&store, false, usize::MAX, &mut || false)
    });
    assert!(result.is_none(), "step {point} was not reached");
    assert_eq!(trace, reference[..=point], "kill at step {point}");
}

/// A kill at every deletion step of a small tree, then a rerun, leaves the
/// tree one uninterrupted run leaves, and a third run performs no unlink.
/// A second kill at every unlink of the rerun leaves a tree reconciliation
/// accepts, and a further rerun again finishes the same removal.
#[test]
fn a_kill_at_every_deletion_step_then_a_rerun_equals_one_run() {
    let reference = kill_tree();
    let store = Store::open(&reference.state).unwrap();
    let (swept, trace) = scripted([], || {
        probes(&store, false, usize::MAX, &mut || false).unwrap()
    });
    drop(store);
    assert_eq!(swept.unwrap().removed, ["probe-a", "probe-b"]);
    let once = snapshot(&reference.state);
    assert_eq!(points(&trace, &[Step::Unlink]).len(), 14, "{trace:?}");
    for point in points(&trace, &[Step::Unlink, Step::Sync]) {
        let case = kill_tree();
        killed(&case, point, &trace);
        accepted_by_reconciliation(&case.state.join("probes/probe-a"), point);
        let store = Store::open(&case.state).unwrap();
        let (rerun, retrace) = scripted([], || {
            probes(&store, false, usize::MAX, &mut || false).unwrap()
        });
        drop(store);
        assert!(rerun.is_some(), "kill at step {point}");
        assert_eq!(snapshot(&case.state), once, "kill at step {point}");
        let store = Store::open(&case.state).unwrap();
        let (third, steps) = scripted([], || {
            probes(&store, false, usize::MAX, &mut || false).unwrap()
        });
        drop(store);
        let third = third.unwrap();
        assert!(third.removed.is_empty(), "kill at step {point}");
        assert_eq!(
            reasons(&third),
            BTreeMap::from([("probe-z", LISTING_SOURCE)])
        );
        assert!(!steps.contains(&Step::Unlink), "kill at step {point}");
        assert_eq!(snapshot(&case.state), once, "kill at step {point}");
        for second in points(&retrace, &[Step::Unlink]) {
            let case = kill_tree();
            killed(&case, point, &trace);
            killed(&case, second, &retrace);
            let context = format!("kills at steps {point} and {second}");
            accepted_by_reconciliation(&case.state.join("probes/probe-a"), point);
            sweep(&case);
            assert_eq!(snapshot(&case.state), once, "{context}");
        }
    }
}

/// An `EIO` at any step of a sweep stops it with a host fault and no later
/// unlink, and before the first unlink it leaves the tree unchanged. A
/// rerun then finishes the removal one uninterrupted run performs.
#[test]
fn an_io_fault_at_every_step_stops_the_sweep_and_a_rerun_finishes_it() {
    let reference = kill_tree();
    let before = snapshot(&reference.state);
    let store = Store::open(&reference.state).unwrap();
    let (_, trace) = scripted([], || {
        probes(&store, false, usize::MAX, &mut || false).unwrap()
    });
    drop(store);
    let once = snapshot(&reference.state);
    let first = trace.iter().position(|step| *step == Step::Unlink).unwrap();
    for index in 0..trace.len() {
        let case = kill_tree();
        let store = Store::open(&case.state).unwrap();
        let (result, steps) = scripted([(index, Outcome::Errno(libc::EIO))], || {
            probes(&store, false, usize::MAX, &mut || false)
        });
        drop(store);
        let context = format!("EIO at step {index} {:?}", trace[index]);
        let error = result.unwrap().unwrap_err();
        assert!(error.host_fault(), "{context}: {error}");
        assert!(!steps[index + 1..].contains(&Step::Unlink), "{context}");
        if index <= first {
            assert_eq!(snapshot(&case.state), before, "{context}");
        }
        sweep(&case);
        assert_eq!(snapshot(&case.state), once, "{context}");
    }
}

/// Requires the probe tree a kill left to be one probe reconciliation
/// accepts for an unreserved probe: `started` only beside `intent`, and any
/// other entry only beside `finished`.
fn accepted_by_reconciliation(probe: &Path, point: usize) {
    if !probe.exists() {
        return;
    }
    let has = |entry: &str| probe.join(entry).exists();
    assert!(!has("reservation"), "kill at step {point}");
    assert!(!has("started") || has("intent"), "kill at step {point}");
    let other = [
        "intent",
        "started",
        "artifacts",
        "launcher.stdout",
        "launcher.stderr",
    ];
    assert!(
        !other.iter().any(|entry| has(entry)) || has("finished"),
        "kill at step {point}"
    );
}

/// A dry run leaves the tree byte-identical and reports the removal a real
/// run then performs, which leaves the kept probe whole.
#[test]
fn a_dry_run_writes_nothing_and_reports_the_real_run() {
    let case = kill_tree();
    let before = snapshot(&case.state);
    let shown = crate::campaign::collect::collect(&case.state, true).unwrap();
    assert_eq!(snapshot(&case.state), before);
    assert_eq!(
        shown["probes"]["removed"],
        serde_json::json!(["probe-a", "probe-b"])
    );
    let done = crate::campaign::collect::collect(&case.state, false).unwrap();
    assert_eq!(done["probes"], shown["probes"]);
    assert_eq!(
        snapshot(&case.state),
        without(before, &["probe-a", "probe-b"])
    );
}

/// An unlisted file, a name outside the store's name rules, a staged entry
/// or a foreign mark in the evidence store, a symlink inside a probe
/// directory, or records that probe reconciliation holds keep that
/// directory, a dry run plans the same, and the symlink's target is
/// untouched.
#[test]
fn unlisted_entries_and_symlinks_keep_their_probe_directory() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let damaged = [
        "probe-artifacts-extra",
        "probe-corrupt",
        "probe-no-intent-evidence",
        "probe-partial-held",
        "probe-evidence",
        "probe-finished-other",
        "probe-hidden",
        "probe-intent-other",
        "probe-link",
        "probe-marker-bytes",
        "probe-marker-dir",
        "probe-marker-link",
        "probe-staged",
        "probe-staging-file",
        "probe-staging-link",
        "probe-started-alone",
        "probe-started-corrupt",
        "probe-started-other",
        "probe-stream-link",
        "probe-unknown",
    ];
    for probe in damaged {
        released_probe(&store, probe, GONE);
    }
    released_probe(&store, "probe-removed", GONE);
    released_probe(&store, "probe-source", GONE);
    drop(store);
    let probe = |probe: &str| case.state.join("probes").join(probe);
    let evidence = |name: &str| probe(name).join("artifacts/probe");
    let replace = |path: &Path, bytes: &[u8]| {
        fs::remove_file(path).unwrap();
        fs::write(path, bytes).unwrap();
    };
    fs::write(probe("probe-corrupt").join("finished"), b"{").unwrap();
    fs::write(probe("probe-started-corrupt").join("started"), b"{").unwrap();
    for record in ["intent", "finished"] {
        let other = probe(&format!("probe-{record}-other")).join(record);
        replace(
            &other,
            &fs::read(probe("probe-source").join(record)).unwrap(),
        );
    }
    fs::remove_file(probe("probe-started-alone").join("intent")).unwrap();
    for entry in ["intent", "started"] {
        fs::remove_file(probe("probe-no-intent-evidence").join(entry)).unwrap();
    }
    fs::copy(
        probe("probe-source").join("started"),
        probe("probe-started-other").join("started"),
    )
    .unwrap();
    fs::write(
        probe("probe-artifacts-extra").join("artifacts/extra"),
        b"keep",
    )
    .unwrap();
    fs::remove_file(evidence("probe-partial-held").join("artifact")).unwrap();
    fs::write(case.state.join("probes/probe-file"), b"keep").unwrap();
    let target = case.root.join("target");
    fs::write(&target, b"target bytes").unwrap();
    let evidence_stream = evidence("probe-stream-link").join("capabilities.stdout");
    fs::remove_file(&evidence_stream).unwrap();
    std::os::unix::fs::symlink(&target, &evidence_stream).unwrap();
    let stream = probe("probe-link").join("launcher.stdout");
    fs::remove_file(&stream).unwrap();
    std::os::unix::fs::symlink(&target, &stream).unwrap();
    fs::write(probe("probe-hidden").join(".hidden"), b"keep").unwrap();
    fs::write(evidence("probe-staged").join(".staging/staged"), b"keep").unwrap();
    fs::write(probe("probe-unknown").join("extra"), b"keep").unwrap();
    fs::write(evidence("probe-evidence").join("extra"), b"keep").unwrap();
    replace(&evidence("probe-marker-bytes").join(".state"), b"foreign\n");
    fs::remove_file(evidence("probe-marker-dir").join(".state")).unwrap();
    fs::create_dir(evidence("probe-marker-dir").join(".state")).unwrap();
    fs::remove_file(evidence("probe-marker-link").join(".state")).unwrap();
    std::os::unix::fs::symlink(&target, evidence("probe-marker-link").join(".state")).unwrap();
    fs::remove_dir(evidence("probe-staging-file").join(".staging")).unwrap();
    fs::write(evidence("probe-staging-file").join(".staging"), b"keep").unwrap();
    fs::remove_dir(evidence("probe-staging-link").join(".staging")).unwrap();
    std::os::unix::fs::symlink(
        case.root.join("outside"),
        evidence("probe-staging-link").join(".staging"),
    )
    .unwrap();
    fs::create_dir(case.root.join("outside")).unwrap();
    let before = without(snapshot(&case.state), &["probe-removed"]);
    let planned = probes(
        &Store::open(&case.state).unwrap(),
        true,
        usize::MAX,
        &mut || false,
    )
    .unwrap();
    let swept = sweep(&case);
    assert_eq!(planned, swept);
    assert_eq!(swept.removed, ["probe-removed"], "{swept:?}");
    assert_eq!(snapshot(&case.state), before);
    let kept = reasons(&swept);
    let mut expected: Vec<_> = damaged.to_vec();
    expected.extend(["probe-file", "probe-source"]);
    expected.sort_unstable();
    assert_eq!(kept.keys().copied().collect::<Vec<_>>(), expected);
    let marks =
        "probe evidence holds staged entries, a foreign mark or entries beside a missing mark";
    for (probe, reason) in [
        (
            "probe-finished-other",
            "probe finished record names another attempt",
        ),
        ("probe-intent-other", "probe intent names another attempt"),
        (
            "probe-corrupt",
            "the record is no JSON of the record domain",
        ),
        (
            "probe-started-corrupt",
            "the record is no JSON of the record domain",
        ),
        (
            "probe-evidence",
            "probe evidence holds unlisted entry extra",
        ),
        (
            "probe-link",
            "probe entry launcher.stdout is no regular file",
        ),
        ("probe-unknown", "probe holds unlisted entry extra"),
        (
            "probe-no-intent-evidence",
            "probe without intent holds evidence",
        ),
        (
            "probe-started-other",
            "probe started record differs from its intent",
        ),
        (
            "probe-artifacts-extra",
            "probe artifacts hold an unlisted entry",
        ),
        (
            "probe-partial-held",
            "probe evidence holds unlisted entry capabilities.stderr",
        ),
        ("probe-marker-bytes", marks),
        ("probe-marker-dir", marks),
        ("probe-marker-link", marks),
        ("probe-source", LISTING_SOURCE),
        ("probe-staged", marks),
        ("probe-staging-file", marks),
        ("probe-staging-link", marks),
        ("probe-started-alone", "started probe requires an intent"),
    ] {
        assert_eq!(kept[probe], reason, "{probe}");
    }
    assert_eq!(kept["probe-hidden"], "probe holds unlisted entry .hidden");
    for probe in ["probe-file", "probe-stream-link"] {
        assert_eq!(
            swept
                .kept
                .iter()
                .find(|row| row.probe == probe)
                .unwrap()
                .code,
            "unreadable",
            "{probe}"
        );
    }
    assert_eq!(fs::read(&target).unwrap(), b"target bytes");
}

/// A symlink to a directory at the probe directory, at `artifacts` or at
/// the evidence store keeps that probe, and the tree it points to is
/// untouched, while a later probe of the build is the listing source.
#[test]
fn linked_directories_keep_their_probe_and_the_outside_tree() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for probe in ["probe-dir", "probe-artifacts", "probe-evidence", "probe-z"] {
        released_probe(&store, probe, GONE);
    }
    drop(store);
    let mut outside = Vec::new();
    for (probe, linked) in [
        ("probe-dir", ""),
        ("probe-artifacts", "artifacts"),
        ("probe-evidence", "artifacts/probe"),
    ] {
        let path = case.state.join("probes").join(probe);
        let path = if linked.is_empty() {
            path
        } else {
            path.join(linked)
        };
        let moved = case.root.join(format!("outside-{probe}"));
        fs::rename(&path, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &path).unwrap();
        outside.push((moved.clone(), snapshot(&moved)));
    }
    let swept = sweep(&case);
    assert!(swept.removed.is_empty(), "{swept:?}");
    assert_eq!(
        reasons(&swept).keys().copied().collect::<Vec<_>>(),
        ["probe-artifacts", "probe-dir", "probe-evidence", "probe-z"]
    );
    for row in &swept.kept {
        assert_eq!(
            row.code,
            if row.probe == "probe-z" {
                SOURCE
            } else {
                "unreadable"
            }
        );
    }
    for (moved, before) in outside {
        assert_eq!(snapshot(&moved), before, "{}", moved.display());
    }
}

/// A probe directory or evidence store listing past the scan bound keeps
/// its probe whole while another probe is removed, and a `probes/` listing
/// past the bound stops the sweep before any unlink.
#[test]
fn listings_past_the_scan_bound_keep_their_probe_or_stop_the_sweep() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    probe(&store, "probe-over", 7);
    probe(&store, "probe-empty", 0);
    released_probe(&store, "probe-nested", GONE);
    released_probe(&store, "probe-z", GONE);
    drop(store);
    for extra in ["extra-1", "extra-2"] {
        fs::write(
            case.state
                .join("probes/probe-nested/artifacts/probe")
                .join(extra),
            b"keep",
        )
        .unwrap();
    }
    let before = without(snapshot(&case.state), &["probe-empty"]);
    let store = Store::open(&case.state).unwrap();
    let (swept, _) = bounded(6, || probes(&store, false, usize::MAX, &mut || false));
    let swept = swept.unwrap();
    assert_eq!(swept.removed, ["probe-empty"]);
    assert_eq!(
        reasons(&swept),
        BTreeMap::from([
            ("probe-nested", "probe holds too many entries"),
            ("probe-over", "probe holds too many entries"),
            ("probe-z", LISTING_SOURCE),
        ])
    );
    assert_eq!(snapshot(&case.state), before);
    let (result, reached) = bounded(2, || probes(&store, false, usize::MAX, &mut || false));
    assert!(
        matches!(result, Err(crate::campaign::Error::Bound { .. })),
        "{result:?}"
    );
    assert!(!reached.contains(&Step::Unlink), "{reached:?}");
    assert_eq!(snapshot(&case.state), before);
}

/// Probe reconciliation accepts the tree a kill leaves at every deletion
/// step of the sweep, so an admission after a killed collect proceeds. A
/// finished probe whose cgroup is live keeps its directory and is reported.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn probe_reconciliation_accepts_every_killed_sweep_prefix() {
    let _processes = crate::store::fixture::processes();
    let live = crate::custody::run_tests::Hosted::new(599999);
    let store = Store::open(&live.case.state).unwrap();
    released_probe(&store, "probe-live", live.root.to_str().unwrap());
    let before = snapshot(&live.case.state);
    let swept = probes(&store, false, usize::MAX, &mut || false).unwrap();
    assert_eq!(
        swept.kept,
        [Kept {
            probe: "probe-live".into(),
            code: "binding",
            reason: "probe cgroup is live".into(),
        }]
    );
    assert_eq!(snapshot(&live.case.state), before);
    drop(store);
    let built = |index| {
        let hosted = crate::custody::run_tests::Hosted::new(index);
        let store = Store::open(&hosted.case.state).unwrap();
        released_probe(&store, "probe-a", GONE);
        released_probe(&store, "probe-z", GONE);
        (hosted, store)
    };
    let reconcile = |hosted: &crate::custody::run_tests::Hosted, store: &Store| {
        let mut custody = hosted.custody(std::time::Duration::from_secs(1));
        crate::campaign::probe::reconcile_records(store, &mut custody).unwrap();
    };
    let (reference, store) = built(600000);
    let (swept, trace) = scripted([], || {
        probes(&store, false, usize::MAX, &mut || false).unwrap()
    });
    drop(store);
    assert_eq!(swept.unwrap().removed, ["probe-a"]);
    let once = snapshot(&reference.case.state);
    assert_eq!(points(&trace, &[Step::Unlink]).len(), 13, "{trace:?}");
    for (offset, point) in points(&trace, &[Step::Unlink, Step::Sync])
        .into_iter()
        .enumerate()
    {
        let (hosted, store) = built(600001 + offset);
        drop(store);
        killed(&hosted.case, point, &trace);
        let store = Store::open(&hosted.case.state).unwrap();
        reconcile(&hosted, &store);
        let (rerun, retrace) = scripted([], || probes(&store, false, usize::MAX, &mut || false));
        rerun.unwrap().unwrap();
        assert_eq!(snapshot(&hosted.case.state), once);
        let (third, third_trace) =
            scripted([], || probes(&store, false, usize::MAX, &mut || false));
        assert!(third.unwrap().unwrap().removed.is_empty());
        assert!(!third_trace.contains(&Step::Unlink));
        assert_eq!(snapshot(&hosted.case.state), once);
        drop(store);
        for (second_offset, second) in points(&retrace, &[Step::Unlink]).into_iter().enumerate() {
            let (hosted, store) = built(610000 + offset * 20 + second_offset);
            drop(store);
            killed(&hosted.case, point, &trace);
            let store = Store::open(&hosted.case.state).unwrap();
            reconcile(&hosted, &store);
            drop(store);
            killed(&hosted.case, second, &retrace);
            let store = Store::open(&hosted.case.state).unwrap();
            reconcile(&hosted, &store);
            probes(&store, false, usize::MAX, &mut || false).unwrap();
            assert_eq!(snapshot(&hosted.case.state), once);
            let (third, third_trace) =
                scripted([], || probes(&store, false, usize::MAX, &mut || false));
            assert!(third.unwrap().unwrap().removed.is_empty());
            assert!(!third_trace.contains(&Step::Unlink));
            assert_eq!(snapshot(&hosted.case.state), once);
        }
    }
}

/// Evidence that changed after publication stays byte-identical, even
/// when a later valid probe supplies the same build's report declaration.
#[test]
fn damaged_or_oversized_streams_keep_their_probe() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for probe in ["probe-stderr", "probe-oversized", "probe-z"] {
        released_probe(&store, probe, GONE);
    }
    drop(store);
    fs::write(
        case.state
            .join("probes/probe-stderr/artifacts/probe/capabilities.stderr"),
        b"changed",
    )
    .unwrap();
    let path = case
        .state
        .join("probes/probe-oversized/artifacts/probe/capabilities.stdout");
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(crate::campaign::probe::OUTPUT_BYTES + 1)
        .unwrap();
    let before = snapshot(&case.state);
    let swept = sweep(&case);
    assert!(swept.removed.is_empty());
    assert_eq!(
        reasons(&swept)["probe-stderr"],
        "probe stream capabilities.stderr digest differs"
    );
    assert_eq!(
        swept
            .kept
            .iter()
            .find(|kept| kept.probe == "probe-oversized")
            .unwrap()
            .code,
        "unreadable"
    );
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn evidence_without_its_marker_keeps_the_probe() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    released_probe(&store, "probe-unmarked", GONE);
    released_probe(&store, "probe-z", GONE);
    drop(store);
    fs::remove_file(
        case.state
            .join("probes/probe-unmarked/artifacts/probe/.state"),
    )
    .unwrap();
    let before = snapshot(&case.state);
    let planned = probes(
        &Store::open(&case.state).unwrap(),
        true,
        usize::MAX,
        &mut || false,
    )
    .unwrap();
    let swept = sweep(&case);
    assert_eq!(planned, swept);
    assert!(swept.removed.is_empty(), "{swept:?}");
    let kept = swept
        .kept
        .iter()
        .find(|kept| kept.probe == "probe-unmarked")
        .unwrap();
    assert_ne!(kept.code, SOURCE);
    assert_eq!(reasons(&swept)["probe-z"], LISTING_SOURCE);
    assert_eq!(snapshot(&case.state), before);
}

fn kept_unchanged(damage: impl FnOnce(&Path)) {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    released_probe(&store, "probe-damaged", GONE);
    released_probe(&store, "probe-z", GONE);
    drop(store);
    damage(&case.state.join("probes/probe-damaged"));
    let before = snapshot(&case.state);
    let planned = probes(
        &Store::open(&case.state).unwrap(),
        true,
        usize::MAX,
        &mut || false,
    )
    .unwrap();
    let swept = sweep(&case);
    assert_eq!(planned, swept);
    assert!(swept.removed.is_empty(), "{swept:?}");
    let kept = swept
        .kept
        .iter()
        .find(|kept| kept.probe == "probe-damaged")
        .unwrap();
    assert_ne!(kept.code, SOURCE);
    assert_eq!(reasons(&swept)["probe-z"], LISTING_SOURCE);
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn artifacts_without_a_started_record_keep_the_probe() {
    kept_unchanged(|probe| fs::remove_file(probe.join("started")).unwrap());
}

#[test]
fn a_later_stream_missing_beside_an_earlier_one_keeps_the_probe() {
    kept_unchanged(|probe| {
        fs::remove_file(probe.join("artifacts/probe/capabilities.stderr")).unwrap();
    });
}

#[test]
fn a_launcher_stderr_missing_beside_its_stdout_keeps_the_probe() {
    kept_unchanged(|probe| {
        fs::remove_dir_all(probe.join("artifacts")).unwrap();
        fs::remove_file(probe.join("launcher.stderr")).unwrap();
    });
}

#[test]
fn artifacts_without_a_launcher_stream_keep_the_probe() {
    kept_unchanged(|probe| fs::remove_file(probe.join("launcher.stdout")).unwrap());
}

#[test]
fn an_entry_added_during_evidence_removal_stops_before_unmarking() {
    let case = kill_tree();
    let evidence = case.state.join("probes/probe-a/artifacts/probe");
    let path = evidence.join("extra");
    let store = Store::open(&case.state).unwrap();
    let mut unlinks = 0;
    let result = observed(
        move |step| {
            if step == Step::Unlink {
                unlinks += 1;
                if unlinks == 3 {
                    fs::write(&path, b"keep").unwrap();
                }
            }
        },
        || probes(&store, false, usize::MAX, &mut || false),
    );
    assert!(result.is_err(), "{result:?}");
    assert!(evidence.join(".state").exists());
    assert!(evidence.join(".staging").exists());
    assert_eq!(fs::read(evidence.join("extra")).unwrap(), b"keep");
    assert!(case.state.join("probes/probe-b").exists());
}

#[test]
fn a_released_probe_that_stopped_before_its_start_is_removed() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    released_probe(&store, "probe-early", GONE);
    released_probe(&store, "probe-z", GONE);
    drop(store);
    let probe = case.state.join("probes/probe-early");
    fs::remove_file(probe.join("started")).unwrap();
    fs::remove_dir_all(probe.join("artifacts")).unwrap();
    let expected = without(snapshot(&case.state), &["probe-early"]);
    let swept = sweep(&case);
    assert_eq!(swept.removed, ["probe-early"]);
    assert_eq!(snapshot(&case.state), expected);
}

#[test]
fn a_released_probe_that_stopped_between_its_launcher_streams_is_removed() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    released_probe(&store, "probe-early", GONE);
    released_probe(&store, "probe-z", GONE);
    drop(store);
    let probe = case.state.join("probes/probe-early");
    fs::remove_file(probe.join("started")).unwrap();
    fs::remove_dir_all(probe.join("artifacts")).unwrap();
    fs::remove_file(probe.join("launcher.stderr")).unwrap();
    let expected = without(snapshot(&case.state), &["probe-early"]);
    let swept = sweep(&case);
    assert_eq!(swept.removed, ["probe-early"], "{swept:?}");
    assert_eq!(snapshot(&case.state), expected);
}

/// A later verifying probe held for an extra entry leaves an earlier
/// removable verified source intact, with its precise source designation.
#[test]
fn a_later_held_listing_keeps_an_earlier_removable_source() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    released_probe(&store, "probe-a", GONE);
    released_probe(&store, "probe-z", GONE);
    drop(store);
    fs::write(case.state.join("probes/probe-z/extra"), b"keep").unwrap();
    let before = snapshot(&case.state);
    let swept = sweep(&case);
    assert!(swept.removed.is_empty());
    assert_eq!(reasons(&swept)["probe-a"], LISTING_SOURCE);
    assert_eq!(
        reasons(&swept)["probe-z"],
        "probe holds unlisted entry extra"
    );
    assert_eq!(snapshot(&case.state), before);
}

/// A full probes/ listing at the bound is sweepable. A nested evidence
/// listing at its exact bound and report's probe listing also complete.
#[test]
fn listings_at_the_bound_complete() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for index in 0..6 {
        probe(&store, &format!("probe-{index}"), 0);
    }
    let (swept, _) = bounded(6, || probes(&store, false, usize::MAX, &mut || false));
    assert_eq!(swept.unwrap().removed.len(), 6);
    released_probe(&store, "probe-source", GONE);
    let mut evidence = store.root().duplicate().unwrap();
    for component in ["probes", "probe-source", "artifacts", "probe"] {
        evidence = store
            .open_dir(&evidence, &crate::campaign::name(component))
            .unwrap()
            .unwrap();
    }
    assert_eq!(store.list_nested(&evidence, 5).unwrap().len(), 3);
    for index in 0..5 {
        probe(&store, &format!("probe-empty-{index}"), 0);
    }
    drop(store);
    bounded(6, || crate::campaign::report(&case.state))
        .0
        .expect("the report probe listing completes at exactly the bound");
    let swept = sweep(&case);
    assert_eq!(swept.removed.len(), 5);
    assert_eq!(reasons(&swept)["probe-source"], LISTING_SOURCE);
}

/// A current-tree replan refuses an extra entry that appears after the
/// first pass, preserving every original entry of the affected probe.
#[test]
fn an_entry_added_between_planning_and_removal_keeps_the_probe() {
    let case = kill_tree();
    let path = case.state.join("probes/probe-a/extra");
    let before = snapshot(&case.state);
    let mut added = false;
    let store = Store::open(&case.state).unwrap();
    let result = observed(
        move |step| {
            if step == Step::Sync && !added {
                fs::write(&path, b"keep").unwrap();
                added = true;
            }
        },
        || probes(&store, false, usize::MAX, &mut || false),
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "probe holds unlisted entry extra"
    );
    fs::remove_file(case.state.join("probes/probe-a/extra")).unwrap();
    assert_eq!(snapshot(&case.state), before);
}

/// Staging that appears during evidence deletion preserves the nested
/// marker and stops the pass before any later probe is removed.
#[test]
fn staging_added_during_removal_stops_before_unmarking() {
    let case = kill_tree();
    let path = case
        .state
        .join("probes/probe-a/artifacts/probe/.staging/entry");
    let store = Store::open(&case.state).unwrap();
    let mut unlinks = 0;
    let result = observed(
        move |step| {
            if step == Step::Unlink {
                unlinks += 1;
                if unlinks == 3 {
                    fs::write(&path, b"keep").unwrap();
                }
            }
        },
        || probes(&store, false, usize::MAX, &mut || false),
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "probe evidence changed before its marks were removed"
    );
    assert!(
        case.state
            .join("probes/probe-a/artifacts/probe/.state")
            .exists()
    );
    assert_eq!(
        fs::read(
            case.state
                .join("probes/probe-a/artifacts/probe/.staging/entry")
        )
        .unwrap(),
        b"keep"
    );
    assert!(case.state.join("probes/probe-b").exists());
}

/// A recorded path outside the cgroup tree is a per-probe refusal and
/// leaves the evidence intact while another probe is removed.
#[test]
fn a_non_cgroup_path_keeps_its_probe() {
    let case = kill_tree();
    let store = Store::open(&case.state).unwrap();
    finished_probe(
        &store,
        "probe-invalid-group",
        case.root.to_str().unwrap(),
        Digest::of(b"archive"),
        ProbeOutcome::Held,
    );
    let before = snapshot(&case.state.join("probes/probe-invalid-group"));
    let swept = probes(&store, false, usize::MAX, &mut || false).unwrap();
    assert_eq!(swept.removed, ["probe-a", "probe-b"]);
    assert_eq!(
        swept
            .kept
            .iter()
            .find(|kept| kept.probe == "probe-invalid-group")
            .unwrap()
            .code,
        "unreadable"
    );
    assert_eq!(
        snapshot(&case.state.join("probes/probe-invalid-group")),
        before
    );
}

/// Each deletion reopens its directory chain and file identity. A moved
/// probe, replaced evidence directory or replaced stream remains intact
/// after the first deletion, and the sweep stops at the next recheck.
#[test]
fn changed_probe_paths_stop_the_next_deletion() {
    for change in ["probe", "evidence", "stream"] {
        let case = kill_tree();
        let probe = case.state.join("probes/probe-a");
        let evidence = probe.join("artifacts/probe");
        let original = if change == "probe" {
            probe.clone()
        } else if change == "evidence" {
            evidence.clone()
        } else {
            evidence.join("capabilities.stderr")
        };
        let outside = case.root.join("moved");
        let mut expected = if change == "stream" {
            Snapshot::new()
        } else {
            snapshot(&original)
        };
        expected.remove(&if change == "probe" {
            Path::new("artifacts/probe/capabilities.stdout").to_owned()
        } else {
            Path::new("capabilities.stdout").to_owned()
        });
        let moved = outside.clone();
        let mut unlinked = false;
        let mut changed = false;
        let store = Store::open(&case.state).unwrap();
        let result = observed(
            move |step| {
                if step == Step::Unlink {
                    unlinked = true;
                }
                if step == Step::Sync && unlinked && !changed {
                    fs::rename(&original, &moved).unwrap();
                    if change == "evidence" {
                        fs::create_dir(&original).unwrap();
                    }
                    if change == "stream" {
                        fs::write(&original, b"replacement").unwrap();
                    }
                    changed = true;
                }
            },
            || probes(&store, false, usize::MAX, &mut || false),
        );
        assert!(result.is_err(), "{change}: {result:?}");
        if change == "stream" {
            assert_eq!(fs::read(&outside).unwrap(), b"");
            assert_eq!(
                fs::read(evidence.join("capabilities.stderr")).unwrap(),
                b"replacement"
            );
        } else {
            assert_eq!(snapshot(&outside), expected);
            if change == "evidence" {
                assert!(snapshot(&evidence).is_empty());
            }
        }
        assert!(case.state.join("probes/probe-b").exists());
    }
}

/// A source whose freshly verified build differs from its planned build
/// stops collection before any probe is deleted.
#[test]
fn a_listing_source_build_changed_since_planning_stops_the_sweep() {
    let case = kill_tree();
    let store = std::rc::Rc::new(Store::open(&case.state).unwrap());
    let mut directory = store.root().duplicate().unwrap();
    for component in ["probes", "probe-z", "artifacts", "probe"] {
        directory = store
            .open_dir(&directory, &crate::campaign::name(component))
            .unwrap()
            .unwrap();
    }
    let mut artifact = store
        .read_record::<crate::record::Artifact>(&directory, &crate::campaign::name("artifact"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    artifact.archive = Some(Digest::of(b"changed build"));
    let writer = store.clone();
    let mut changed = false;
    let result = observed(
        move |step| {
            if step == Step::Sync && !changed {
                writer
                    .replace_record(&directory, &crate::campaign::name("artifact"), &artifact)
                    .unwrap();
                changed = true;
            }
        },
        || probes(&store, false, usize::MAX, &mut || false),
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "probe build changed since planning"
    );
    assert!(
        case.state
            .join("probes/probe-a/artifacts/probe/capabilities.stdout")
            .is_file()
    );
    assert!(case.state.join("probes/probe-b").is_dir());
}

#[test]
fn a_finite_probe_budget_and_an_observed_stop_preserve_the_remaining_probes() {
    for limit in [0, 1, 2, 3] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        for index in 0..3 {
            probe(&store, &format!("probe-{index}"), 0);
        }
        let result = probes(&store, false, limit, &mut || false).unwrap();
        assert_eq!(result.removed.len(), limit);
        assert_eq!(result.stopped, limit < 3);
        assert_eq!(
            fs::read_dir(case.state.join("probes")).unwrap().count(),
            3 - limit
        );
    }
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    probe(&store, "probe-stop", 0);
    let before = snapshot(&case.state);
    let mut calls = 0;
    let result = probes(&store, false, usize::MAX, &mut || {
        calls += 1;
        calls == 1
    })
    .unwrap();
    assert!(result.stopped);
    assert!(result.removed.is_empty());
    assert_eq!(calls, 1);
    assert_eq!(snapshot(&case.state), before);
}

fn source_tree() -> Case {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for probe in ["probe-a", "probe-b", "probe-z"] {
        released_probe(&store, probe, GONE);
    }
    drop(store);
    case
}

#[test]
fn a_listing_source_damaged_during_removal_keeps_the_next_probe() {
    let case = source_tree();
    let profiles = crate::campaign::report(&case.state).unwrap()["profiles"].clone();
    let kept = snapshot(&case.state.join("probes/probe-b"));
    let listing = case
        .state
        .join("probes/probe-z/artifacts/probe/capabilities.stdout");
    let damaged = std::rc::Rc::new(std::cell::Cell::new(false));
    let fired = damaged.clone();
    let store = Store::open(&case.state).unwrap();
    let result = observed(
        move |step| {
            if step == Step::Unlink && !fired.get() {
                fs::write(&listing, b"damaged listing").unwrap();
                fired.set(true);
            }
        },
        || probes(&store, false, usize::MAX, &mut || false),
    );
    drop(store);
    assert!(damaged.get());
    assert!(result.is_err(), "{result:?}");
    assert_eq!(snapshot(&case.state.join("probes/probe-b")), kept);
    assert_eq!(
        crate::campaign::report(&case.state).unwrap()["profiles"],
        profiles
    );
}

#[test]
fn a_reservation_on_the_listing_source_during_removal_keeps_the_next_probe() {
    let case = source_tree();
    let profiles = crate::campaign::report(&case.state).unwrap()["profiles"].clone();
    let kept = snapshot(&case.state.join("probes/probe-b"));
    let store = std::rc::Rc::new(Store::open(&case.state).unwrap());
    let mut source = store.root().duplicate().unwrap();
    for component in ["probes", "probe-z"] {
        source = store
            .open_dir(&source, &crate::campaign::name(component))
            .unwrap()
            .unwrap();
    }
    let writer = store.clone();
    let reserved = std::rc::Rc::new(std::cell::Cell::new(false));
    let fired = reserved.clone();
    let result = observed(
        move |step| {
            if step == Step::Unlink && !fired.get() {
                fired.set(true);
                writer
                    .create_record(
                        &source,
                        &crate::campaign::name("reservation"),
                        &crate::record::Reservation {
                            attempt: crate::campaign::text("probe-z").unwrap(),
                        },
                    )
                    .unwrap();
            }
        },
        || probes(&store, false, usize::MAX, &mut || false),
    );
    drop(store);
    assert!(reserved.get());
    assert!(result.is_err(), "{result:?}");
    assert_eq!(snapshot(&case.state.join("probes/probe-b")), kept);
    assert_eq!(
        crate::campaign::report(&case.state).unwrap()["profiles"],
        profiles
    );
}
