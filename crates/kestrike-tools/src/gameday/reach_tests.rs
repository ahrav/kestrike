//! Each row's expected result is the judge's at the base under Python 3.9.25 for the same call: the
//! function the test calls, on the held roles mark with the row's changes applied and the held package.

use super::roles_reach;
use crate::gameday::constants::FILE_LIMIT;
use crate::gameday::layout::layout;
use crate::gameday::test_support::{held, object, patched, tree};
use crate::gameday::{FleetBounds, check_package, conform};
use crate::text::Text;

type Patches = &'static [(&'static str, Option<&'static str>)];
/// A label, the changes to the roles mark, and the judge's unmet conditions.
type Row = (&'static str, Patches, &'static [&'static str]);

#[test]
fn roles_reach_lists_each_unmet_condition_before_the_stop() {
    let package = held("package.json");
    let p = object(&package);
    let bounds = FleetBounds::new(&tree(), FILE_LIMIT).expect("the top holds no NUL");
    let names = check_package(p, &bounds).expect("the held package passes");
    let roles = held("injection/roles.json");
    let (schema, _) = layout("injection/roles.json").expect("a file of the layout");
    #[rustfmt::skip]
    let rows: &[Row] = &[
    (r#"held"#, &[], &[]),
    (r#"owns one"#, &[(r#"shards/s2/owner"#, Some(r#""h2""#)), (r#"shards/s3/owner"#, Some(r#""h3""#))], &[r#"the target owns 1 shards, fewer than 2"#]),
    (r#"stands by for none"#, &[(r#"shards/s4/standby"#, Some(r#""h3""#))], &[r#"the target stands by for 0 shards, fewer than 1"#]),
    (r#"no standby"#, &[(r#"shards/s1/standby"#, Some(r#"null"#))], &[r#"owned shard s1 names no standby other than the target"#]),
    (r#"standby is the target"#, &[(r#"shards/s2/standby"#, Some(r#""h1""#))], &[r#"owned shard s2 names no standby other than the target"#]),
    (r#"standby unread"#, &[(r#"shards/s1/standby"#, Some(r#""h4""#))], &[r#"standby host h4 of s1 has no instance state and host report read before the stop"#]),
    (r#"standby reports the target's instance"#, &[(r#"standbys/h2/instance"#, Some(r#""i-h1""#))], &[r#"standby host h2 of s1 reports the target's instance i-h1"#, r#"standby host h2 of s3 reports the target's instance i-h1"#]),
    (r#"standby stopped"#, &[(r#"standbys/h3/instance_state"#, Some(r#""stopped""#))], &[r#"standby host h3 of s2 reads stopped and healthy"#]),
    (r#"standby unhealthy"#, &[(r#"standbys/h3/host_report"#, Some(r#""impaired""#))], &[r#"standby host h3 of s2 reads running and impaired"#]),
    (r#"all"#, &[(r#"shards/s2/owner"#, Some(r#""h2""#)), (r#"shards/s3/owner"#, Some(r#""h3""#)), (r#"shards/s4/standby"#, Some(r#""h3""#)), (r#"shards/s1/standby"#, Some(r#""h4""#))], &[r#"the target owns 1 shards, fewer than 2"#, r#"the target stands by for 0 shards, fewer than 1"#, r#"standby host h4 of s1 has no instance state and host report read before the stop"#]),
    (r#"none owned"#, &[(r#"shards/s1/owner"#, Some(r#""h2""#)), (r#"shards/s2/owner"#, Some(r#""h2""#)), (r#"shards/s3/owner"#, Some(r#""h2""#))], &[r#"the target owns 0 shards, fewer than 2"#]),
        (r#"owns exactly two"#, &[(r#"shards/s3/owner"#, Some(r#""h3""#))], &[]),
        (r#"standby on the target's instance and stopped"#, &[(r#"standbys/h3/instance"#, Some(r#""i-h1""#)), (r#"standbys/h3/instance_state"#, Some(r#""stopped""#))], &[r#"standby host h3 of s2 reports the target's instance i-h1"#]),
    ];
    for &(label, patches, expected) in rows {
        let changed = patched(&roles, patches);
        conform(
            &changed,
            schema,
            &Text::from("injection/roles.json"),
            &names,
        )
        .expect("the roles conform");
        let found: Vec<String> = roles_reach(object(&changed), p)
            .iter()
            .map(Text::to_string)
            .collect();
        assert_eq!(found, expected, "roles_reach of {label}");
    }
}

/// The judge's self-test case of the same name: the held roles meet every condition, and a shard's
/// standby moved off the target with an unhealthy standby host gives two unmet conditions.
#[test]
fn the_pre_stop_half_of_the_reach_reads_the_roles_and_the_package_alone() {
    let package = held("package.json");
    let roles = held("injection/roles.json");
    assert!(roles_reach(object(&roles), object(&package)).is_empty());
    let changed = patched(
        &roles,
        &[
            ("shards/s4/standby", Some(r#""h3""#)),
            ("standbys/h3/host_report", Some(r#""unhealthy""#)),
        ],
    );
    let found: Vec<String> = roles_reach(object(&changed), object(&package))
        .iter()
        .map(Text::to_string)
        .collect();
    assert_eq!(
        found,
        [
            "the target stands by for 0 shards, fewer than 1",
            "standby host h3 of s2 reads running and unhealthy"
        ]
    );
}

/// The owned shards are read in the package's order: with the package's shards listed as s3, s1, s2, s4,
/// s5 and the roles mark's keys left in their order, the text of s3 comes before that of s1.
#[test]
fn the_owned_shards_are_read_in_the_packages_order() {
    let package = patched(
        &held("package.json"),
        &[("shards", Some(r#"["s3", "s1", "s2", "s4", "s5"]"#))],
    );
    let p = object(&package);
    let bounds = FleetBounds::new(&tree(), FILE_LIMIT).expect("the top holds no NUL");
    let names = check_package(p, &bounds).expect("the reordered package passes");
    let roles = patched(
        &held("injection/roles.json"),
        &[("standbys/h2/instance", Some(r#""i-h1""#))],
    );
    let (schema, _) = layout("injection/roles.json").expect("a file of the layout");
    conform(&roles, schema, &Text::from("injection/roles.json"), &names)
        .expect("the roles conform");
    let found: Vec<String> = roles_reach(object(&roles), p)
        .iter()
        .map(Text::to_string)
        .collect();
    assert_eq!(
        found,
        [
            "standby host h2 of s3 reports the target's instance i-h1",
            "standby host h2 of s1 reports the target's instance i-h1"
        ]
    );
}
