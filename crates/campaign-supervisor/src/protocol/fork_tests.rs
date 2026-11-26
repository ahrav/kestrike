//! Branch and exploration output tests: the parser requires each
//! once-printed line, holds every child, node and leaf, refuses a tally or
//! census that disagrees with its lines, and reads the divergence line as
//! no fork.

use super::fixture::{BRANCH, EXPLORE, edited, twice, without};
use super::{Branch, ChildClass, Error, Explore, Limits, Outcome, Terminal, Upload};

const DIVERGED: &str = "parent: diverged before the milestone\n";

#[test]
fn a_branch_parses_every_child_and_the_witness_values() {
    let branch = Branch::parse(BRANCH)
        .expect("the fixture parses")
        .expect("it forked");
    assert_eq!(branch.milestone.name, "pending-put");
    assert_eq!(
        (
            branch.milestone.boundary,
            branch.milestone.semantic,
            branch.milestone.decisions
        ),
        (13, 501, 100)
    );
    let witness = &branch.witness;
    assert_eq!(
        (
            witness.milestone.as_str(),
            witness.holds,
            witness.boundary,
            witness.upload,
            witness.armed
        ),
        (
            "pending-put",
            true,
            13,
            Some(Upload {
                attempt: 1,
                grant: 3,
                held: 2,
                outcome: 0
            }),
            false
        )
    );
    assert!(branch.reproduced && branch.problems.is_empty());
    let pairs: Vec<_> = branch
        .children
        .iter()
        .map(|child| (child.suffix, child.sibling))
        .collect();
    assert_eq!(pairs, [(0, 0), (0, 1)]);
    let (digest, terminal) = branch.children[1].report.expect("a parsed report");
    assert_eq!(
        digest.to_string(),
        "1f27fb908bebec8fe9cd01041d338f6565bef18f41ee2d4567bb73df1dfa035c"
    );
    assert_eq!(
        terminal,
        Terminal::Complete {
            outcome: Outcome::Pass,
            fired: 3,
            required: 3
        }
    );
}

#[test]
fn a_branch_child_without_a_report_and_its_problems_parse() {
    let text = edited(
        BRANCH,
        "sibling=1 class=success digest=1f27fb908bebec8fe9cd01041d338f6565bef18f41ee2d4567bb73df1dfa035c terminal=complete pass fired=03 required=03",
        "sibling=1 class=watchdog",
    );
    let text = edited(
        &text,
        "branch: 2 children, 2 credited, 0 problems",
        "problem: suffix 0 sibling 1: hung\nbranch: 2 children, 1 credited, 1 problems",
    );
    let branch = Branch::parse(&text)
        .expect("the edited fixture parses")
        .expect("it forked");
    assert_eq!(
        (branch.children[1].class, &branch.children[1].report),
        (ChildClass::Watchdog, &None)
    );
    assert_eq!(branch.problems, ["suffix 0 sibling 1: hung"]);
    let none = Branch::parse(&edited(
        BRANCH,
        "upload=attempt:1,grant:3,held:2,outcome:0",
        "upload=none",
    ));
    assert_eq!(
        none.map(|branch| branch.map(|branch| branch.witness.upload)),
        Ok(Some(None))
    );
}

/// The prefix replay's divergence line alone parses as no fork; doubled it
/// is refused as repeated, and beside any other line it is refused.
#[test]
fn the_divergence_line_parses_as_no_fork() {
    assert_eq!(Branch::parse(DIVERGED), Ok(None));
    assert_eq!(Explore::parse(DIVERGED), Ok(None));
    assert_eq!(
        Branch::parse(&format!("{DIVERGED}{BRANCH}")),
        Err(Error::Repeated("parent".to_owned()))
    );
    assert_eq!(
        Branch::parse(&format!("{DIVERGED}witness: x\n")),
        Err(Error::Unknown("witness".to_owned()))
    );
    let doubled = format!("{DIVERGED}{DIVERGED}");
    let repeated = Error::Repeated("parent".to_owned());
    assert_eq!(Branch::parse(&doubled), Err(repeated.clone()));
    assert_eq!(Explore::parse(&doubled), Err(repeated));
}

/// A parent whose replay no longer reproduces the bundle parses as not
/// reproduced in both forms, beside the problem each form names for it.
#[test]
fn a_changed_parent_parses_as_not_reproduced() {
    let branched = edited(
        &edited(BRANCH, "parent: reproduced", "parent: changed"),
        "branch: 2 children, 2 credited, 0 problems",
        "problem: the parent's replay no longer reproduces the bundle\nbranch: 2 children, 2 credited, 1 problems",
    );
    let branch = Branch::parse(&branched)
        .expect("the edited fixture parses")
        .expect("it forked");
    assert!(!branch.reproduced);
    assert_eq!(
        branch.problems,
        ["the parent's replay no longer reproduces the bundle"]
    );
    let explored = edited(
        &edited(EXPLORE, "parent: reproduced", "parent: changed"),
        "frontier:",
        "problem: the root's replay no longer reproduces the bundle\nfrontier:",
    );
    let explored = edited(&explored, "0 problems", "1 problems");
    let explore = Explore::parse(&explored)
        .expect("the edited fixture parses")
        .expect("it forked");
    assert!(!explore.reproduced);
    assert_eq!(
        explore.problems,
        ["the root's replay no longer reproduces the bundle"]
    );
}

/// Each child class word parses as its class and no other word does.
#[test]
fn each_child_class_word_names_its_class() {
    let words = [
        ("success", ChildClass::Success),
        ("failed", ChildClass::Failed),
        ("mismatch", ChildClass::Mismatch),
        ("signaled", ChildClass::Signaled),
        ("silent", ChildClass::Silent),
        ("malformed", ChildClass::Malformed),
        ("watchdog", ChildClass::Watchdog),
        ("lost", ChildClass::Lost),
    ];
    for (word, class) in words {
        assert_eq!(ChildClass::parse(word, "child"), Ok(class), "{word}");
        assert_eq!(class.name(), word);
    }
    assert_eq!(ChildClass::ALL, words.map(|(_, class)| class));
    assert_eq!(
        ChildClass::parse("Success", "child"),
        Err(Error::Value("child"))
    );
}

/// A failing exploration parses with its failed node, its non-counting
/// leaf and its problem, which the census and tally count.
#[test]
fn a_failing_exploration_parses_its_failures() {
    let text = edited(
        EXPLORE,
        "leaf: path=0.0",
        "node: path=1 class=failed wall_us=900 cpu_us=800 max_rss_kib=700\nleaf: path=0.0",
    );
    let text = edited(
        &text,
        "counts=true verdict=complete pass fired=03 required=03",
        "counts=false verdict=complete violation fired=03 required=03",
    );
    let text = edited(
        &text,
        "frontier: nodes=2 credited=2 explored=1 failing=0",
        "problem: 1: failed\nfrontier: nodes=3 credited=2 explored=1 failing=1",
    );
    let text = edited(&text, "0 problems", "1 problems");
    let explore = Explore::parse(&text)
        .expect("the edited fixture parses")
        .expect("it forked");
    let classes: Vec<_> = explore.nodes.iter().map(|node| node.class).collect();
    assert_eq!(
        classes,
        [ChildClass::Success, ChildClass::Success, ChildClass::Failed]
    );
    let leaf = &explore.leaves[0];
    assert!(!leaf.counts && !leaf.verdict.passes());
    assert_eq!(explore.problems, ["1: failed"]);
}

#[test]
fn each_once_printed_fork_line_is_required_exactly_once() {
    for key in ["milestone", "witness", "parent", "branch"] {
        assert_eq!(
            Branch::parse(&without(BRANCH, key)),
            Err(Error::Missing(key)),
            "{key}"
        );
        assert_eq!(
            Branch::parse(&twice(BRANCH, key)),
            Err(Error::Repeated(key.to_owned())),
            "{key}"
        );
    }
    for key in [
        "label",
        "milestone",
        "witness",
        "limits",
        "parent",
        "frontier",
        "explore",
    ] {
        assert_eq!(
            Explore::parse(&without(EXPLORE, key)),
            Err(Error::Missing(key)),
            "{key}"
        );
        assert_eq!(
            Explore::parse(&twice(EXPLORE, key)),
            Err(Error::Repeated(key.to_owned())),
            "{key}"
        );
    }
    assert_eq!(Branch::parse(&BRANCH[..BRANCH.len() - 1]), Err(Error::Torn));
    assert_eq!(
        Explore::parse(&EXPLORE[..EXPLORE.len() - 1]),
        Err(Error::Torn)
    );
}

#[test]
fn fork_lines_that_disagree_are_refused() {
    let tally = Err(Error::Inconsistent(
        "the branch tally disagrees with its lines",
    ));
    assert_eq!(Branch::parse(&without(BRANCH, "child")), tally);
    assert_eq!(
        Branch::parse(&edited(BRANCH, "2 credited", "1 credited")),
        tally
    );
    assert_eq!(Branch::parse(&format!("problem: lost\n{BRANCH}")), tally);
    assert_eq!(
        Branch::parse(&twice(BRANCH, "child")),
        Err(Error::Repeated("child suffix=0 sibling=0".to_owned()))
    );
    let elsewhere = Err(Error::Inconsistent(
        "the witness names another milestone or boundary",
    ));
    assert_eq!(
        Branch::parse(&edited(
            BRANCH,
            "holds=true boundary=13",
            "holds=true boundary=12"
        )),
        elsewhere
    );
    assert_eq!(
        Branch::parse(&edited(
            BRANCH,
            "witness: pending-put",
            "witness: recovery-reached"
        )),
        elsewhere
    );
    let denied = Error::Inconsistent("the witness denies the milestone the run forked at");
    assert_eq!(
        Branch::parse(&edited(BRANCH, "holds=true", "holds=false")),
        Err(denied.clone())
    );
    assert_eq!(
        Explore::parse(&edited(EXPLORE, "holds=true", "holds=false")),
        Err(denied)
    );
    let census = Err(Error::Inconsistent(
        "the exploration census disagrees with its lines",
    ));
    assert_eq!(Explore::parse(&without(EXPLORE, "leaf")), census);
    assert_eq!(
        Explore::parse(&twice(EXPLORE, "node")),
        Err(Error::Repeated("node path=0".to_owned()))
    );
    assert_eq!(
        Explore::parse(&twice(EXPLORE, "leaf")),
        Err(Error::Repeated("leaf path=0.0".to_owned()))
    );
    let orphan = Err(Error::Inconsistent(
        "a node names no printed success node as its parent",
    ));
    assert_eq!(
        Explore::parse(&edited(EXPLORE, "node: path=0 class", "node: path=1 class")),
        orphan
    );
    let stray = Err(Error::Inconsistent("a leaf names no printed success node"));
    assert_eq!(
        Explore::parse(&edited(EXPLORE, "leaf: path=0.0", "leaf: path=0.1")),
        stray
    );
    assert_eq!(
        Explore::parse(&edited(
            EXPLORE,
            "node: path=0 class=success",
            "node: path=0 class=failed"
        )),
        census
    );
    assert_eq!(
        Explore::parse(&edited(EXPLORE, "0 problems", "1 problems")),
        Err(Error::Inconsistent(
            "the exploration tally disagrees with its problems"
        ))
    );
    // The census's unexplored total covers the leaf's four candidates.
    assert_eq!(
        Explore::parse(&edited(
            EXPLORE,
            "unexplored=4\nexplore",
            "unexplored=3\nexplore"
        )),
        census
    );
    assert!(
        Explore::parse(&edited(
            EXPLORE,
            "unexplored=4\nexplore",
            "unexplored=9\nexplore"
        ))
        .is_ok()
    );
    let counting = Err(Error::Inconsistent(
        "a leaf counts beside a verdict that does not pass",
    ));
    for verdict in [
        "complete violation fired=03 required=03",
        "infrastructure cap",
        "complete pass fired=01 required=03",
    ] {
        assert_eq!(
            Explore::parse(&edited(
                EXPLORE,
                "verdict=complete pass fired=03 required=03",
                &format!("verdict={verdict}")
            )),
            counting,
            "{verdict}"
        );
    }
}

/// A leaf's node is a success node, and a child prints a report only
/// beside the success class.
#[test]
fn reports_and_leaves_print_only_beside_success() {
    assert_eq!(
        Explore::parse(&edited(
            EXPLORE,
            "node: path=0.0 class=success",
            "node: path=0.0 class=watchdog"
        )),
        Err(Error::Inconsistent("a leaf names no printed success node"))
    );
    let failed = edited(
        BRANCH,
        "sibling=1 class=success digest=",
        "sibling=1 class=failed digest=",
    );
    assert_eq!(
        Branch::parse(&failed),
        Err(Error::Inconsistent(
            "a child prints a report beside a class other than success"
        ))
    );
}

/// A leaf that does not count beside a passing verdict parses: a bundle
/// whose campaign withholds credit passes without counting.
#[test]
fn a_passing_leaf_need_not_count() {
    let text = edited(EXPLORE, "counts=true verdict=", "counts=false verdict=");
    let text = edited(&text, "failing=0", "failing=1");
    let explore = Explore::parse(&text)
        .expect("the edited fixture parses")
        .expect("it forked");
    let leaf = &explore.leaves[0];
    assert!(!leaf.counts && leaf.verdict.passes());
}

/// The census's unexplored total covers the sum over every leaf, not the
/// largest leaf alone, and a sum past `u64::MAX` is refused.
#[test]
fn the_unexplored_total_covers_every_leaf() {
    let two = |first: &str, second: &str, total: &str| {
        let text = edited(
            EXPLORE,
            "leaf: path=0.0",
            "node: path=1 class=success wall_us=9 cpu_us=8 max_rss_kib=7\nleaf: path=0.0",
        );
        let text = edited(
            &text,
            "unexplored=4 counts",
            &format!("unexplored={first} counts"),
        );
        let text = edited(
            &text,
            "frontier:",
            &format!(
                "leaf: path=1 digest={} unexplored={second} counts=true verdict=complete pass fired=03 required=03\nfrontier:",
                "31f1b1c901ee0a3672fc8538d1358a95f6fceebf11014b6fe861fd97d2b3441f"
            ),
        );
        let text = edited(
            &text,
            "nodes=2 credited=2 explored=1",
            "nodes=3 credited=3 explored=2",
        );
        let text = edited(
            &text,
            "unexplored=4\nexplore",
            &format!("unexplored={total}\nexplore"),
        );
        Explore::parse(&text)
    };
    let census = Err(Error::Inconsistent(
        "the exploration census disagrees with its lines",
    ));
    assert!(two("4", "3", "7").is_ok());
    assert_eq!(two("4", "3", "6"), census);
    assert_eq!(two("4", "3", "4"), census);
    let max = u64::MAX.to_string();
    assert_eq!(two(&max, "1", &max), census);
}

/// Each fork form refuses a line of a key it never prints.
#[test]
fn a_fork_line_of_another_key_is_unknown() {
    let foreign = |text: &str| format!("{text}stage: x\n");
    assert_eq!(
        Branch::parse(&foreign(BRANCH)),
        Err(Error::Unknown("stage".to_owned()))
    );
    assert_eq!(
        Explore::parse(&foreign(EXPLORE)),
        Err(Error::Unknown("stage".to_owned()))
    );
}

#[test]
fn fork_values_outside_their_form_are_refused() {
    for (from, to, error) in [
        (
            "class=success digest=1f27",
            "class=winner digest=1f27",
            Error::Value("child"),
        ),
        (
            "suffix=0 sibling=0",
            "suffix=00 sibling=0",
            Error::Value("child"),
        ),
        ("digest=1f27", "digest=zz1f27", Error::Value("child")),
        ("holds=true", "holds=yes", Error::Value("witness")),
        (
            "upload=attempt:1,",
            "upload=attempt:x,",
            Error::Value("witness"),
        ),
        (
            "parent: reproduced",
            "parent: replayed",
            Error::Value("parent"),
        ),
        ("prefix=555e", "prefix=555E", Error::Value("milestone")),
        (
            "2 children, 2 credited",
            "two children, 2 credited",
            Error::Value("branch"),
        ),
    ] {
        assert_eq!(
            Branch::parse(&edited(BRANCH, from, to)),
            Err(error),
            "{from} -> {to}"
        );
    }
    for (from, to, error) in [
        (
            "label: composed-bounded",
            "label: bounded",
            Error::Value("label"),
        ),
        ("depth=2", "depth=two", Error::Value("limits")),
        (
            "max_rss_kib=21332\nnode",
            "max_rss_kib=lots\nnode",
            Error::Value("node"),
        ),
        ("counts=true", "counts=1", Error::Value("leaf")),
        (
            "unexplored=4\nexplore",
            "unexplored=-4\nexplore",
            Error::Value("frontier"),
        ),
        (
            "composed-bounded, 0 problems",
            "composed-bounded, no problems",
            Error::Value("explore"),
        ),
        ("frontier:", "problem: \nfrontier:", Error::Value("problem")),
    ] {
        assert_eq!(
            Explore::parse(&edited(EXPLORE, from, to)),
            Err(error),
            "{from} -> {to}"
        );
    }
    for size in ["-1", "+21332", "021332", "9223372036854775808"] {
        let text = edited(
            EXPLORE,
            "max_rss_kib=21332\nnode",
            &format!("max_rss_kib={size}\nnode"),
        );
        assert_eq!(Explore::parse(&text), Err(Error::Value("node")), "{size}");
    }
    // A node's and a leaf's path change together, so only the path's form
    // refuses it.
    for path in ["0.x", "00.0", "0.65536", "0..0", "", ".0", "0.", "root"] {
        let text = EXPLORE.replace("path=0.0", &format!("path={path}"));
        assert_eq!(Explore::parse(&text), Err(Error::Value("node")), "{path:?}");
    }
    let widest = EXPLORE.replace("path=0.0", "path=0.65535");
    assert!(Explore::parse(&widest).is_ok());
}

#[test]
fn an_exploration_parses_every_node_and_leaf() {
    let explore = Explore::parse(EXPLORE)
        .expect("the fixture parses")
        .expect("it forked");
    assert_eq!(
        explore.limits,
        Limits {
            depth: 2,
            children: 3,
            faults: 12,
            advances: 16
        }
    );
    assert_eq!(explore.nodes.len(), 2);
    let node = &explore.nodes[1];
    assert_eq!(
        (
            node.path.as_str(),
            node.class,
            node.wall_us,
            node.cpu_us,
            node.max_rss_kib
        ),
        ("0.0", ChildClass::Success, 3650, 3672, 21400)
    );
    let leaf = &explore.leaves[0];
    assert_eq!(
        (leaf.path.as_str(), leaf.unexplored, leaf.counts),
        ("0.0", 4, true)
    );
    assert!(leaf.verdict.passes());
    assert_eq!(explore.unexplored, 4);
}
