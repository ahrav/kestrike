//! Each row's expected result is the judge's own function's at the base under Python 3.9.25, as the
//! expression beside it gives it.

use std::fs;

use super::{FleetBounds, check_package};
use crate::gameday::constants::FILE_LIMIT;
use crate::gameday::schema::{Names, sorted};
use crate::gameday::test_support::{held, object, patched, tree, value};
use crate::json::Value;
use crate::paths::tests::Scratch;

const HOSTS: &str = "crates/kestrike/src/failover/zone_loop/directory.rs";
const SLOTS: &str = "crates/kestrike/src/failover/standbys.rs";

/// The names in the order the rows write them.
fn shown(names: &Names) -> String {
    ["host", "shard", "observation", "budget", "key"]
        .iter()
        .map(|kind| {
            format!(
                "{kind}={}",
                sorted(names.get(kind).expect("a kind").iter().cloned())
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// A tree that holds the two declaring files with the bytes given, or without the file for `None`.
fn declaring(hosts: Option<&[u8]>, slots: Option<&[u8]>) -> Scratch {
    let scratch = Scratch::new("gameday-bounds");
    for (rel, data) in [(HOSTS, hosts), (SLOTS, slots)] {
        if let Some(data) = data {
            let path = scratch.0.join(rel);
            fs::create_dir_all(path.parent().expect("a parent")).expect("the directories are made");
            fs::write(path, data).expect("the declaration is written");
        }
    }
    scratch
}

type Patches = &'static [(&'static str, Option<&'static str>)];
/// The bytes of the two declaring files, each absent for `None`.
type Declarations = Option<(Option<&'static [u8]>, Option<&'static [u8]>)>;
/// A label, the changes to the package, the tree of the declarations, and the judge's result.
type Row = (
    &'static str,
    Patches,
    Declarations,
    Result<&'static str, &'static str>,
);

#[test]
fn check_package_passes_the_held_package_and_refuses_each_changed_copy() {
    let package = held("package.json");
    #[rustfmt::skip]
    let rows: &[Row] = &[
    (r#"held"#, &[], None, Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
    (r#"note absent"#, &[(r#"note"#, None)], None, Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
    (r#"hosts past MAX_HOSTS"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 3;\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Err(r#"package.json hosts holds 4 entries, more than the 3 that MAX_HOSTS of crates/kestrike/src/failover/zone_loop/directory.rs declares"#)),
    (r#"hosts at MAX_HOSTS"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 4;\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
    (r#"shards past MAX_SLOTS"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 4096;\x0a"), Some(b"pub const MAX_SLOTS: usize = 4;\x0a"))), Err(r#"package.json shards holds 5 entries, more than the 4 that MAX_SLOTS of crates/kestrike/src/failover/standbys.rs declares"#)),
    (r#"witness past MAX_SLOTS"#, &[(r#"witness"#, Some(r#"[1, 2, 3, 4, 5, 6]"#))], Some((Some(b"pub const MAX_HOSTS: usize = 4096;\x0a"), Some(b"pub const MAX_SLOTS: usize = 5;\x0a"))), Err(r#"package.json witness holds 6 entries, more than the 5 that MAX_SLOTS of crates/kestrike/src/failover/standbys.rs declares"#)),
    (r#"bound past the hosts that are no list"#, &[(r#"hosts"#, Some(r#""h1""#))], Some((Some(b"pub const MAX_HOSTS: usize = 0;\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Err(r#"package.json hosts is no list"#)),
    (r#"bound file absent"#, &[], Some((None, Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Err(r#"crates/kestrike/src/failover/zone_loop/directory.rs cannot be read: No such file or directory"#)),
    (r#"bound with CRLF"#, &[], Some((Some(b"// x\x0d\x0apub const MAX_HOSTS: usize = 4;\x0d\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
    (r#"bound with a lone CR"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 4;\x0d"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Err(r#"crates/kestrike/src/failover/zone_loop/directory.rs declares MAX_HOSTS 0 times as `pub const MAX_HOSTS: usize = N;`, not once"#)),
    (r#"bound declared twice"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 4;\x0apub const MAX_HOSTS: usize = 5;\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Err(r#"crates/kestrike/src/failover/zone_loop/directory.rs declares MAX_HOSTS 2 times as `pub const MAX_HOSTS: usize = N;`, not once"#)),
    (r#"bound declared nowhere"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 4 ;\x0aconst MAX_HOSTS: usize = 4;\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Err(r#"crates/kestrike/src/failover/zone_loop/directory.rs declares MAX_HOSTS 0 times as `pub const MAX_HOSTS: usize = N;`, not once"#)),
    (r#"bound past 64 bits"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 18446744073709551616;\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Err(r#"crates/kestrike/src/failover/zone_loop/directory.rs declares MAX_HOSTS as a value past a 64-bit usize"#)),
    (r#"bound at 64 bits"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 18446744073709551615;\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
    (r#"bound of 21 digits"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 000000000000000000004;\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Err(r#"crates/kestrike/src/failover/zone_loop/directory.rs declares MAX_HOSTS as a value past a 64-bit usize"#)),
    (r#"bound not UTF-8"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 4;\x0a\xff\x0a"), Some(b"pub const MAX_SLOTS: usize = 4096;\x0a"))), Err(r#"crates/kestrike/src/failover/zone_loop/directory.rs is not UTF-8: 'utf-8' codec can't decode byte 0xff in position 32: invalid start byte"#)),
    (r#"hosts no list"#, &[(r#"hosts"#, Some(r#""h1""#))], None, Err(r#"package.json hosts is no list"#)),
    (r#"hosts absent"#, &[(r#"hosts"#, None)], None, Err(r#"package.json hosts is no list"#)),
    (r#"hosts entry no name"#, &[(r#"hosts/1"#, Some(r#"" ""#))], None, Err(r#"package.json hosts [1] is no name of the layout: ' '"#)),
    (r#"hosts empty"#, &[(r#"hosts"#, Some(r#"[]"#))], None, Err(r#"package.json hosts is empty or repeats a name"#)),
    (r#"shards repeat"#, &[(r#"shards/1"#, Some(r#""s1""#))], None, Err(r#"package.json shards is empty or repeats a name"#)),
    (r#"extra key"#, &[(r#"extra"#, Some(r#"1"#))], None, Err(r#"package.json holds the keys ['baseline', 'clock', 'clock_error_seconds', 'date', 'extra', 'hosts', 'id', 'interval', 'kind', 'outside', 'reconciler_principal', 'revision', 'run', 'shards', 'target', 'witness', 'working_budgets'], not ['baseline', 'clock', 'clock_error_seconds', 'date', 'hosts', 'id', 'interval', 'kind', 'outside', 'reconciler_principal', 'revision', 'run', 'shards', 'target', 'witness', 'working_budgets']"#)),
    (r#"key absent"#, &[(r#"clock"#, None)], None, Err(r#"package.json holds the keys ['baseline', 'clock_error_seconds', 'date', 'hosts', 'id', 'interval', 'kind', 'outside', 'reconciler_principal', 'revision', 'run', 'shards', 'target', 'witness', 'working_budgets'], not ['baseline', 'clock', 'clock_error_seconds', 'date', 'hosts', 'id', 'interval', 'kind', 'outside', 'reconciler_principal', 'revision', 'run', 'shards', 'target', 'witness', 'working_budgets']"#)),
    (r#"id"#, &[(r#"id"#, Some(r#""GD-3""#))], None, Err(r#"package.json id 'GD-3' is none of ['GD-2']"#)),
    (r#"kind"#, &[(r#"kind"#, Some(r#""causal""#))], None, Err(r#"package.json kind 'causal' is none of ['simulation', 'staging']"#)),
    (r#"revision"#, &[(r#"revision"#, Some(r#""abc""#))], None, Err(r#"package.json revision is no commit of the layout: 'abc'"#)),
    (r#"date"#, &[(r#"date"#, Some(r#""2026-02-30""#))], None, Err(r#"package.json date is no date of the layout: '2026-02-30'"#)),
    (r#"target host"#, &[(r#"target/host"#, Some(r#""h9""#))], None, Err(r#"package.json target host is no host of the layout: 'h9'"#)),
    (r#"shard name"#, &[(r#"shards/0"#, Some(r#""receipts""#)), (r#"witness/0/shard"#, Some(r#""receipts""#))], None, Err(r#"package.json shards [0] is no file-name of the layout: 'receipts'"#)),
    (r#"witness shard"#, &[(r#"witness/0/shard"#, Some(r#""s9""#))], None, Err(r#"package.json witness [0] shard is no shard of the layout: 's9'"#)),
    (r#"witness sha256"#, &[(r#"witness/2/sha256"#, Some(r#""x""#))], None, Err(r#"package.json witness [2] sha256 is no digest of the layout: 'x'"#)),
    (r#"baseline"#, &[(r#"baseline"#, Some(r#"{"start": 0}"#))], None, Err(r#"package.json baseline holds the keys ['start'], not ['end', 'start']"#)),
    (r#"interval zero"#, &[(r#"interval"#, Some(r#"0"#))], None, Err(r#"package.json interval is no positive of the layout: 0"#)),
    (r#"working budget"#, &[(r#"working_budgets/drain"#, Some(r#"1"#))], None, Err(r#"package.json working_budgets names ['drain', 'origin-load', 're-enrollment-drain'], not only the budgets ['origin-load', 're-enrollment-drain']"#)),
    (r#"working budget value"#, &[(r#"working_budgets/origin-load"#, Some(r#"-1"#))], None, Err(r#"package.json working_budgets origin-load is no positive of the layout: -1"#)),
    (r#"outside unknown"#, &[(r#"outside/network"#, Some(r#""x""#))], None, Err(r#"package.json outside names ['network'], not only the observations ['origin', 'provider', 're-enrollment']"#)),
    (r#"clock error"#, &[(r#"clock_error_seconds"#, Some(r#"-1"#))], None, Err(r#"package.json clock_error_seconds is no nonnegative of the layout: -1"#)),
    (r#"note"#, &[(r#"note"#, Some(r#"1"#))], None, Err(r#"package.json note is no name of the layout: 1"#)),
    (r#"note blank"#, &[(r#"note"#, Some(r#""  ""#))], None, Err(r#"package.json note is no name of the layout: '  '"#)),
    (r#"witness key repeat"#, &[(r#"witness/1/key"#, Some(r#""img/k1""#))], None, Err(r#"package.json repeats a witness key"#)),
    (r#"baseline empty"#, &[(r#"baseline/end"#, Some(r#"0"#))], None, Err(r#"the windows are empty, or the baseline window ends after the run window or before it starts"#)),
    (r#"baseline after run"#, &[(r#"baseline/end"#, Some(r#"500"#)), (r#"run/end"#, Some(r#"450"#))], None, Err(r#"the windows are empty, or the baseline window ends after the run window or before it starts"#)),
    (r#"baseline before run"#, &[(r#"baseline/end"#, Some(r#"50"#))], None, Err(r#"the windows are empty, or the baseline window ends after the run window or before it starts"#)),
    (r#"run empty"#, &[(r#"run/start"#, Some(r#"100"#)), (r#"run/end"#, Some(r#"100"#)), (r#"baseline/end"#, Some(r#"100"#))], None, Err(r#"the windows are empty, or the baseline window ends after the run window or before it starts"#)),
    (r#"interval not whole"#, &[(r#"interval"#, Some(r#"7"#))], None, Err(r#"the run window is not a whole number of origin intervals, from 1 to 1000000"#)),
    (r#"interval 0.1"#, &[(r#"interval"#, Some(r#"0.1"#))], None, Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
    (r#"interval fractional windows"#, &[(r#"baseline/end"#, Some(r#"100.5"#)), (r#"run/start"#, Some(r#"100.5"#)), (r#"run/end"#, Some(r#"400.5"#)), (r#"interval"#, Some(r#"0.1"#))], None, Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
    (r#"intervals past the most"#, &[(r#"interval"#, Some(r#"0.0001"#))], None, Err(r#"the run window is not a whole number of origin intervals, from 1 to 1000000"#)),
    (r#"intervals at the most"#, &[(r#"interval"#, Some(r#"0.0003"#))], None, Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
    (r#"interval past the run"#, &[(r#"interval"#, Some(r#"301"#))], None, Err(r#"the run window is not a whole number of origin intervals, from 1 to 1000000"#)),
    (r#"simulation clock error"#, &[(r#"kind"#, Some(r#""simulation""#)), (r#"clock_error_seconds"#, Some(r#"1"#))], None, Err(r#"a simulation package names a clock error other than 0"#)),
    (r#"simulation clock error -0.0"#, &[(r#"kind"#, Some(r#""simulation""#)), (r#"clock_error_seconds"#, Some(r#"-0.0"#)), (r#"outside/origin"#, Some(r#""none""#))], None, Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
    (r#"staging outside"#, &[(r#"outside/origin"#, Some(r#""none""#)), (r#"outside/provider"#, Some(r#""none""#))], None, Err(r#"a staging package names ['origin', 'provider'] as outside its world"#)),
    (r#"staging clock error"#, &[(r#"clock_error_seconds"#, Some(r#"0.5"#))], None, Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
        (r#"two defects: hosts empty, id"#, &[(r#"hosts"#, Some(r#"[]"#)), (r#"id"#, Some(r#""GD-3""#))], None, Err(r#"package.json hosts is empty or repeats a name"#)),
        (r#"two defects: id, note"#, &[(r#"id"#, Some(r#""GD-3""#)), (r#"note"#, Some(r#"1"#))], None, Err(r#"package.json id 'GD-3' is none of ['GD-2']"#)),
        (r#"two defects: note, witness key"#, &[(r#"note"#, Some(r#"1"#)), (r#"witness/1/key"#, Some(r#""img/k1""#))], None, Err(r#"package.json note is no name of the layout: 1"#)),
        (r#"two defects: witness key, windows"#, &[(r#"witness/1/key"#, Some(r#""img/k1""#)), (r#"baseline/end"#, Some(r#"0"#))], None, Err(r#"package.json repeats a witness key"#)),
        (r#"two defects: windows, interval"#, &[(r#"baseline/end"#, Some(r#"0"#)), (r#"interval"#, Some(r#"7"#))], None, Err(r#"the windows are empty, or the baseline window ends after the run window or before it starts"#)),
        (r#"two defects: interval, clock error"#, &[(r#"interval"#, Some(r#"7"#)), (r#"kind"#, Some(r#""simulation""#)), (r#"clock_error_seconds"#, Some(r#"1"#))], None, Err(r#"the run window is not a whole number of origin intervals, from 1 to 1000000"#)),
        (r#"two defects: clock error, outside"#, &[(r#"kind"#, Some(r#""simulation""#)), (r#"clock_error_seconds"#, Some(r#"1"#)), (r#"outside/origin"#, Some(r#""x""#))], None, Err(r#"a simulation package names a clock error other than 0"#)),
        (r#"one interval"#, &[(r#"interval"#, Some(r#"300"#))], None, Ok(r#"host=['h1', 'h2', 'h3', 'h4']; shard=['s1', 's2', 's3', 's4', 's5']; observation=['origin', 'provider', 're-enrollment']; budget=['origin-load', 're-enrollment-drain']; key=['img/k1', 'img/k2', 'img/k3']"#)),
        (r#"both lists past their bounds"#, &[], Some((Some(b"pub const MAX_HOSTS: usize = 3;\n"), Some(b"pub const MAX_SLOTS: usize = 4;\n"))), Err(r#"package.json hosts holds 4 entries, more than the 3 that MAX_HOSTS of crates/kestrike/src/failover/zone_loop/directory.rs declares"#)),
    ];
    for &(label, patches, top, expected) in rows {
        let scratch = top.map(|(hosts, slots)| declaring(hosts, slots));
        let top = scratch
            .as_ref()
            .map_or_else(tree, |scratch| scratch.0.clone());
        let bounds = FleetBounds::new(&top, FILE_LIMIT).expect("the top holds no NUL");
        let p = patched(&package, patches);
        let found = check_package(object(&p), &bounds)
            .map(|names| shown(&names))
            .map_err(|refusal| refusal.to_string());
        let expected = expected.map(str::to_owned).map_err(|judged| match label {
            "bound not UTF-8" => {
                assert_eq!(
                    judged.split_once(": ").map(|(head, _)| head),
                    Some(&*format!("{HOSTS} is not UTF-8"))
                );
                format!("{HOSTS} is not UTF-8: invalid utf-8 sequence of 1 bytes from index 32")
            }
            _ => judged.to_owned(),
        });
        assert_eq!(found, expected, "check_package of {label}");
    }
}

#[test]
fn a_bound_read_is_held_and_a_refused_read_is_not() {
    let scratch = declaring(None, Some(b"pub const MAX_SLOTS: usize = 4096;\n"));
    let bounds = FleetBounds::new(&scratch.0, FILE_LIMIT).expect("the top holds no NUL");
    let refused = bounds.fleet_bound("hosts").expect_err("the file is absent");
    assert_eq!(
        refused.to_string(),
        format!("{HOSTS} cannot be read: No such file or directory")
    );
    fs::create_dir_all(scratch.0.join(HOSTS).parent().expect("a parent")).expect("made");
    fs::write(scratch.0.join(HOSTS), "pub const MAX_HOSTS: usize = 7;\n").expect("written");
    assert_eq!(
        bounds.fleet_bound("hosts"),
        Ok(7),
        "the refusal was not held"
    );
    fs::write(scratch.0.join(HOSTS), "pub const MAX_HOSTS: usize = 9;\n").expect("written");
    assert_eq!(
        bounds.fleet_bound("hosts"),
        Ok(7),
        "the value read first is held"
    );
    fs::remove_file(scratch.0.join(SLOTS)).expect("removed");
    assert!(
        bounds.fleet_bound("shards").is_err(),
        "the slots were never read"
    );
}

#[test]
fn a_top_with_a_nul_byte_is_refused_at_construction() {
    let top = std::path::Path::new(std::ffi::OsStr::new("a\0b"));
    assert!(FleetBounds::new(top, FILE_LIMIT).is_none());
}

/// The judge's self-test case of the same name, at the tree's own bounds: each list filled to its bound
/// passes, one entry more is refused, and a last entry of another type is refused by the count first.
#[test]
fn lists_past_the_fleets_declared_bounds_are_refused_before_any_set_is_built() {
    let bounds = FleetBounds::new(&tree(), FILE_LIMIT).expect("the top holds no NUL");
    #[rustfmt::skip]
    let rows: &[(&str, &str, &str)] = &[
        ("hosts", "MAX_HOSTS", HOSTS),
        ("shards", "MAX_SLOTS", SLOTS),
        ("witness", "MAX_SLOTS", SLOTS),
    ];
    for &(field, name, rel) in rows {
        let bound = bounds
            .fleet_bound(field)
            .expect("the tree declares the bound");
        assert_eq!(bound, 4096, "{rel} declares {name} once");
        let mut p = held("package.json");
        let entry = |at: u64| match field {
            "witness" => value(&format!(
                r#"{{"key": "img/x{at}", "shard": "s1", "sha256": "{}"}}"#,
                "0".repeat(64)
            )),
            _ => value(&format!(r#""x{at}""#)),
        };
        let Some(Value::Array(items)) = object_mut(&mut p).get_mut(field) else {
            panic!("the package holds the list {field}");
        };
        let start = u64::try_from(items.len()).expect("fits");
        items.extend((0..bound - start).map(entry));
        assert!(
            check_package(object(&p), &bounds).is_ok(),
            "{field} at its bound"
        );
        let past = format!(
            "package.json {field} holds 4097 entries, more than the 4096 that {name} of {rel} declares"
        );
        for last in [entry(bound), value("[[]]")] {
            let mut q = p.clone();
            let Some(Value::Array(items)) = object_mut(&mut q).get_mut(field) else {
                panic!("the package holds the list {field}");
            };
            items.push(last);
            let found = check_package(object(&q), &bounds).map_err(|refusal| refusal.to_string());
            assert_eq!(found.err(), Some(past.clone()), "{field} past its bound");
        }
    }
}

/// The judge's self-test case of the same name, with each declaration planted in a tree of its own: the
/// bound each list reads, the lists past them, each declaration the judge refuses, and a missing file, a
/// link and a named pipe, which is refused without blocking.
#[test]
fn a_fleet_bound_is_read_from_its_own_declaration_or_refused() {
    let slots: &[u8] = b"pub const MAX_SLOTS: usize = 5;\n";
    let scratch = declaring(
        Some(b"/// The most hosts.\r\npub const MAX_HOSTS: usize = 4;\r\n"),
        Some(slots),
    );
    let bounds = FleetBounds::new(&scratch.0, FILE_LIMIT).expect("the top holds no NUL");
    let read: Vec<u64> = ["hosts", "shards", "witness"]
        .iter()
        .map(|field| bounds.fleet_bound(field).expect("a bound"))
        .collect();
    assert_eq!(
        read,
        [4, 5, 5],
        "[gj.fleet_bound(f) for f in ('hosts', 'shards', 'witness')]"
    );
    let witness = |at: &str| {
        format!(
            r#"{{"key": "img/x{at}", "shard": "s1", "sha256": "{}"}}"#,
            "0".repeat(64)
        )
    };
    let (first, second, ninth) = (witness("0"), witness("1"), witness("9"));
    let mut p = held("package.json");
    for added in [&first, &second] {
        let Some(Value::Array(items)) = object_mut(&mut p).get_mut("witness") else {
            panic!("a list");
        };
        items.push(value(added));
    }
    assert!(
        check_package(object(&p), &bounds).is_ok(),
        "five witness keys pass"
    );
    #[rustfmt::skip]
    let rows: &[(&str, &str, &str)] = &[
        ("hosts", r#""h5""#, "package.json hosts holds 5 entries, more than the 4 that MAX_HOSTS of crates/kestrike/src/failover/zone_loop/directory.rs declares"),
        ("shards", r#""s6""#, "package.json shards holds 6 entries, more than the 5 that MAX_SLOTS of crates/kestrike/src/failover/standbys.rs declares"),
        ("witness", &ninth, "package.json witness holds 6 entries, more than the 5 that MAX_SLOTS of crates/kestrike/src/failover/standbys.rs declares"),
    ];
    for &(field, entry, expected) in rows {
        let mut q = p.clone();
        let Some(Value::Array(items)) = object_mut(&mut q).get_mut(field) else {
            panic!("a list");
        };
        items.push(value(entry));
        let found = check_package(object(&q), &bounds).map_err(|refusal| refusal.to_string());
        assert_eq!(
            found.err().as_deref(),
            Some(expected),
            "{field} past its planted bound"
        );
    }
    let nines = |count: usize| "9".repeat(count);
    let declarations: Vec<(Vec<u8>, Result<u64, String>)> = vec![
        (
            b"pub const MAX_HOSTS: usize = 1 << 12;\n".to_vec(),
            Err(format!(
                "{HOSTS} declares MAX_HOSTS 0 times as `pub const MAX_HOSTS: usize = N;`, not once"
            )),
        ),
        (
            b"pub const MAX_HOSTS: usize = 4;\npub const MAX_HOSTS: usize = 4;\n".to_vec(),
            Err(format!(
                "{HOSTS} declares MAX_HOSTS 2 times as `pub const MAX_HOSTS: usize = N;`, not once"
            )),
        ),
        (
            b"pub const MAX_HOSTS: usize = 18446744073709551616;\n".to_vec(),
            Err(format!(
                "{HOSTS} declares MAX_HOSTS as a value past a 64-bit usize"
            )),
        ),
        (
            format!("pub const MAX_HOSTS: usize = {};\n", nines(5000)).into_bytes(),
            Err(format!(
                "{HOSTS} declares MAX_HOSTS as a value past a 64-bit usize"
            )),
        ),
        (
            format!(
                "pub const MAX_HOSTS: usize = 4;\npub const MAX_HOSTS: usize = {};\n",
                nines(30)
            )
            .into_bytes(),
            Err(format!(
                "{HOSTS} declares MAX_HOSTS 2 times as `pub const MAX_HOSTS: usize = N;`, not once"
            )),
        ),
        (
            b"pub const MAX_HOSTS: usize = 4;\n\xff\n".to_vec(),
            Err(format!(
                "{HOSTS} is not UTF-8: invalid utf-8 sequence of 1 bytes from index 32"
            )),
        ),
        (
            b"pub const MAX_HOSTS: usize = 18446744073709551615;\n".to_vec(),
            Ok(u64::MAX),
        ),
    ];
    for (text, expected) in declarations {
        let scratch = declaring(Some(&text), Some(slots));
        let bounds = FleetBounds::new(&scratch.0, FILE_LIMIT).expect("the top holds no NUL");
        let found = check_package(object(&held("package.json")), &bounds)
            .map_err(|refusal| refusal.to_string())
            .and_then(|_| {
                bounds
                    .fleet_bound("hosts")
                    .map_err(|refusal| refusal.to_string())
            });
        assert_eq!(
            found,
            expected,
            "{}",
            String::from_utf8_lossy(&text[..text.len().min(60)])
        );
    }
    let scratch = declaring(None, Some(slots));
    let path = scratch.0.join(HOSTS);
    fs::create_dir_all(path.parent().expect("a parent")).expect("the directories are made");
    fs::write(
        scratch.0.join("valid.rs"),
        "pub const MAX_HOSTS: usize = 4;\n",
    )
    .expect("written");
    #[rustfmt::skip]
    let kinds: &[(&str, &str)] = &[
        ("missing", "cannot be read: No such file or directory"),
        ("link", "cannot be read: Too many levels of symbolic links"),
        ("fifo", "is no regular file"),
    ];
    for &(kind, words) in kinds {
        let _ = fs::remove_file(&path);
        match kind {
            "link" => {
                std::os::unix::fs::symlink(scratch.0.join("valid.rs"), &path).expect("linked")
            }
            "fifo" => {
                let made = std::process::Command::new("mkfifo").arg(&path).status();
                assert!(made.expect("mkfifo starts").success(), "the fifo is made");
            }
            _ => {}
        }
        let bounds = FleetBounds::new(&scratch.0, FILE_LIMIT).expect("the top holds no NUL");
        let found = check_package(object(&held("package.json")), &bounds)
            .map_err(|refusal| refusal.to_string());
        assert_eq!(
            found.err(),
            Some(format!("{HOSTS} {words}")),
            "the declaring file is a {kind}"
        );
    }
}

fn object_mut(value: &mut Value) -> &mut crate::json::Object {
    match value {
        Value::Object(object) => object,
        _ => panic!("an object"),
    }
}
