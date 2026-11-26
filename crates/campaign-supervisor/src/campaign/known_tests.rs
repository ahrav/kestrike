//! A row explains exactly the violation keys of its obligation and rule
//! in its profiles. The table check names each row the worker's listing
//! or rule catalog refutes.

use super::{Bug, KNOWN, Row, defects, explains};
use crate::protocol::{CAPABILITIES, Listing, Rules};
use crate::record::Digest;

const RULE: &str = "a stale hit";
const FOREIGN: &str = "a GET returned bytes no upload of its key wrote";

const ROW: Row = Row {
    issue: 225,
    class: Bug::Correctness,
    pin: "h1-get-stale",
    profiles: &["upload", "h1-get"],
    obligation: 2,
    rule: RULE,
};

/// A version 2 failure identity of `variant` at `site`. The fixture
/// encodes `code` as the obligation byte and hashes the bytes of `rule`,
/// with a zero audit class, length and tail.
fn identity(variant: u8, code: u8, site: u8, rule: &str) -> String {
    let digest = Digest::of(rule.as_bytes());
    format!("02{variant:02x}{code:02x}00{site:02x}0000{digest}0000000000")
}

fn listing() -> Listing {
    let upload = "profile: upload class=live support=implemented campaign=unqualified \
                  held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\n";
    let profile = |name: &str, class: &str| {
        upload.replace("upload class=live", &format!("{name} class={class}"))
    };
    let added = [
        profile("h1-get", "history expected=pass"),
        profile("h1-get-stale", "history expected=violation"),
        profile("h1-get-foreign", "history expected=violation"),
        profile("h1-get-other", "history expected=violation"),
        profile("h1-get-unheld", "history expected=unsuccessful"),
        profile("planted", "control"),
        profile("r1-recover", "recovery"),
    ]
    .concat();
    let base = include_str!("../../testdata/admission-listing.txt");
    assert!(base.contains(upload));
    let text = base
        .replacen(
            "capabilities: 1",
            &format!("capabilities: {CAPABILITIES}"),
            1,
        )
        .replacen(upload, &format!("{upload}{added}"), 1)
        + &format!("fails: h1-get-stale violation 2 {RULE}\n")
        + &format!("fails: h1-get-foreign violation 2 {FOREIGN}\n")
        + &format!("fails: h1-get-other violation 1 {RULE}\n")
        + "fails: h1-get-unheld unsuccessful old read held\n";
    Listing::parse(&text).unwrap()
}

fn rules() -> Rules {
    Rules::parse(&format!(
        "rules: 1\nrule: history {RULE}\nrule: cluster {FOREIGN}\n"
    ))
    .unwrap()
}

#[test]
fn each_bug_class_prints_its_report_name() {
    assert_eq!(
        [Bug::Safety, Bug::Correctness, Bug::Minor].map(Bug::name),
        ["safety bug", "correctness bug", "minor bug"]
    );
}

/// A row explains a `violation` key whose identity carries its obligation
/// and the digest of its rule in each profile it names: variants 1 and 2
/// both match at sites 1 and 2. `explains` returns `None` for another
/// class carrying the same identity, `other`, a panic, another
/// obligation, rule, profile or identity version, and variant 4 with the
/// row's code and digest. Of two matching rows, the first explains the
/// key.
#[test]
fn a_row_explains_only_a_violation_of_its_rule_in_its_profiles() {
    let table = [ROW];
    for variant in [1, 2] {
        for site in [1, 2] {
            let key = format!("violation: {}", identity(variant, 2, site, RULE));
            for profile in ["upload", "h1-get"] {
                assert_eq!(explains(&table, profile, &key), Some(0), "{key} {profile}");
            }
            assert_eq!(explains(&table, "cluster-broad", &key), None, "{key}");
            for class in ["replay differs", "control passed", "wall limit"] {
                let other = key.replacen("violation", class, 1);
                assert_eq!(explains(&table, "upload", &other), None, "{other}");
            }
        }
    }
    let matched = identity(1, 2, 1, RULE);
    for key in [
        "other".to_owned(),
        format!("panic: {matched}"),
        "panic: src/net/owner.rs:1:1".to_owned(),
        "violation: ".to_owned(),
        format!("violation: {}", identity(1, 1, 1, RULE)),
        format!("violation: {}", identity(1, 2, 1, FOREIGN)),
        format!("violation: {}", identity(4, 2, 2, RULE)),
        format!("violation: 01{}", &matched[2..]),
        format!("violation: {}", &matched[..87]),
        format!("violation: {matched}0"),
        format!("violation:{matched}"),
        format!("violation: 0201+2{}", &matched[6..]),
        format!("violation: {}z{}", &matched[..8], &matched[9..]),
        format!("violation: {}A", &matched[..87]),
    ] {
        assert_eq!(explains(&table, "upload", &key), None, "{key}");
    }
    let key = format!("violation: {matched}");
    let second = Row { issue: 226, ..ROW };
    assert_eq!(explains(&[second, ROW], "upload", &key), Some(0));
    let elsewhere = Row {
        profiles: &["cluster-broad"],
        ..ROW
    };
    assert_eq!(explains(&[elsewhere, ROW], "upload", &key), Some(1));
    assert_eq!(explains(&[], "upload", &key), None);
    let pinned = Row {
        profiles: &[],
        ..ROW
    };
    assert_eq!(explains(&[pinned], "upload", &key), None);
    assert_eq!(explains(&[pinned, ROW], "upload", &key), Some(1));
}

#[test]
fn a_loss_in_a_warm_load_sibling_stays_a_new_suspect() {
    let lost = "a retained entry outside every damage set was lost on host loss";
    for variant in [1, 2] {
        let key = format!("violation: {}", identity(variant, 5, 1, lost));
        for profile in ["wl1-closed-without-pass", "wl2-fill-before-pass"] {
            assert_eq!(explains(KNOWN, profile, &key), None, "{profile} {key}");
        }
    }
}

/// Each of these rows pins the one history that runs its defect's trigger.
/// The sibling named beside it judges the same rule where the trigger is
/// absent: `k9-promise-after-close` keeps no placement across the close,
/// `ss2-peer-read-beside-three-commands` submits the peer's read at once,
/// `rs1-wide-unit-without-pass` publishes no checkpoint,
/// `lw1-waiter-submit-accepted` has the device accept every submit, and
/// `lw2-waiter-fragments-one-turn-later` refuses no receive for a buffer.
/// A violation there has another cause and counts as a new suspect. The
/// same key matches the row once it lists the sibling, so the key carries
/// the row's obligation and rule.
#[test]
fn a_violation_in_a_sibling_without_the_trigger_stays_a_new_suspect() {
    const SIBLINGS: [(u32, &[&str]); 5] = [
        (298, &["k9-promise-after-close"]),
        (299, &["ss2-peer-read-beside-three-commands"]),
        (329, &["rs1-wide-unit-without-pass"]),
        (334, &["lw1-waiter-submit-accepted"]),
        (335, &["lw2-waiter-fragments-one-turn-later"]),
    ];
    for (issue, sibling) in SIBLINGS {
        let row = KNOWN.iter().find(|row| row.issue == issue);
        let row = *row.unwrap_or_else(|| panic!("the row of #{issue}"));
        let listed = Row {
            profiles: sibling,
            ..row
        };
        for variant in [1, 2] {
            let identity = identity(variant, row.obligation, 1, row.rule);
            let key = format!("violation: {identity}");
            assert_eq!(explains(KNOWN, sibling[0], &key), None, "#{issue} {key}");
            assert_eq!(explains(&[listed], sibling[0], &key), Some(0), "{key}");
        }
    }
}

/// The table check names the row for each of these defects: a pin that
/// is unlisted, live, expects a pass, declares an unsuccessful ending, or
/// declares a violation of another obligation or under another rule;
/// a rule outside the catalog; a profile named by the row that is
/// unlisted, declares a failure or is a control; and a second row with a
/// profile, obligation and rule in common, where each row names the
/// other. A row that names a profile twice, and rows that share a profile
/// under another obligation or rule, are sound. A rule matches the catalog
/// only as a whole text, and one text lists every profile defect of its
/// row. An empty profile list is sound.
#[test]
fn each_table_defect_is_named() {
    let (listing, rules) = (listing(), rules());
    let check = |table: &[Row]| defects(table, &listing, &rules);
    assert!(check(&[ROW]).is_empty());
    assert!(
        check(&[Row {
            profiles: &["upload", "h1-get", "r1-recover"],
            ..ROW
        }])
        .is_empty()
    );
    assert!(
        check(&[Row {
            profiles: &["upload", "upload"],
            ..ROW
        }])
        .is_empty()
    );
    let pinned = Row {
        profiles: &[],
        ..ROW
    };
    assert!(check(&[pinned]).is_empty());
    assert!(check(&[pinned, pinned, ROW]).is_empty());
    let other_rule = Row {
        pin: "h1-get-foreign",
        rule: FOREIGN,
        ..ROW
    };
    let other_obligation = Row {
        pin: "h1-get-other",
        obligation: 1,
        ..ROW
    };
    assert!(check(&[ROW, other_rule, other_obligation]).is_empty());

    let named = |row: Row, text: &str| {
        assert_eq!(
            check(&[row]),
            [format!("row 0 (issue #225, pin {}): {text}", row.pin)],
        );
    };
    named(
        Row {
            pin: "h9-absent",
            ..ROW
        },
        "pin h9-absent is not listed",
    );
    named(
        Row {
            pin: "upload",
            ..ROW
        },
        "pin upload declares no failure",
    );
    named(
        Row {
            pin: "h1-get",
            ..ROW
        },
        "pin h1-get declares no failure",
    );
    named(
        Row {
            pin: "h1-get-unheld",
            ..ROW
        },
        "pin h1-get-unheld declares an unsuccessful ending",
    );
    named(
        Row {
            obligation: 1,
            ..ROW
        },
        "pin h1-get-stale declares obligation 2 under rule \"a stale hit\"",
    );
    named(
        Row {
            rule: FOREIGN,
            ..ROW
        },
        "pin h1-get-stale declares obligation 2 under rule \"a stale hit\"",
    );
    named(
        Row {
            pin: "h1-get-foreign",
            ..ROW
        },
        "pin h1-get-foreign declares obligation 2 under rule \"a GET returned bytes no upload of \
         its key wrote\"",
    );
    named(
        Row {
            rule: "a stale read",
            ..ROW
        },
        "pin h1-get-stale declares obligation 2 under rule \"a stale hit\"; rule \"a stale read\" is not \
         in the rule catalog",
    );
    named(
        Row {
            rule: "a stale",
            ..ROW
        },
        "pin h1-get-stale declares obligation 2 under rule \"a stale hit\"; rule \"a stale\" is not \
         in the rule catalog",
    );
    named(
        Row {
            rule: "a stale hit.",
            ..ROW
        },
        "pin h1-get-stale declares obligation 2 under rule \"a stale hit\"; rule \"a stale hit.\" is not \
         in the rule catalog",
    );
    named(
        Row {
            profiles: &["upload", "long"],
            ..ROW
        },
        "profile long is not listed",
    );
    named(
        Row {
            profiles: &["h1-get-stale"],
            ..ROW
        },
        "profile h1-get-stale declares a failure",
    );
    named(
        Row {
            profiles: &["h1-get-unheld"],
            ..ROW
        },
        "profile h1-get-unheld declares a failure",
    );
    named(
        Row {
            profiles: &["long", "planted", "h1-get-stale"],
            ..ROW
        },
        "profile long is not listed; profile planted is a control; profile h1-get-stale \
         declares a failure",
    );
    named(
        Row {
            profiles: &["planted"],
            ..ROW
        },
        "profile planted is a control",
    );
    named(
        Row {
            pin: "h1-get",
            profiles: &[],
            ..ROW
        },
        "pin h1-get declares no failure",
    );

    let shared = Row {
        issue: 226,
        profiles: &["h1-get"],
        ..ROW
    };
    let disjoint = Row {
        issue: 1703,
        profiles: &["r1-recover"],
        ..ROW
    };
    let reversed = Row {
        issue: 227,
        profiles: &["h1-get", "upload"],
        ..ROW
    };
    let conflict = |row: usize, issue: u32, details: [(usize, &str); 2]| {
        let details = details.map(|(other, profile)| {
            format!("row {other} also explains obligation 2 under this rule in {profile}")
        });
        format!(
            "row {row} (issue #{issue}, pin h1-get-stale): {}",
            details.join("; ")
        )
    };
    assert_eq!(
        check(&[disjoint, ROW, shared, reversed]),
        [
            conflict(1, 225, [(2, "h1-get"), (3, "upload")]),
            conflict(2, 226, [(1, "h1-get"), (3, "h1-get")]),
            conflict(3, 227, [(1, "h1-get"), (2, "h1-get")]),
        ]
    );
    assert_eq!(
        check(&[ROW, shared]),
        [
            "row 0 (issue #225, pin h1-get-stale): row 1 also explains obligation 2 under \
             this rule in h1-get",
            "row 1 (issue #226, pin h1-get-stale): row 0 also explains obligation 2 under \
             this rule in h1-get",
        ]
    );
}
