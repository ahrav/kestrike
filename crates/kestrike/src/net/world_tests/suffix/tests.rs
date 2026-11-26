//! Suffix trees from recorded milestones, the faulted upload's pending-PUT
//! milestone and the histories' turn and script milestones: the census and
//! its checks, in-process walks that stand for forked nodes and obey the
//! manifest's limits, and the forked trees the worker explores.

use std::cell::RefCell;
use std::path::Path;
use std::time::Duration;

use crate::sim::choice::{Candidate, Chooser, Domain};
use crate::sim::fork::{HOST_FAILED, Refusal, SETUP_FAILED};
use crate::sim::manifest::Manifest;
use crate::sim::trace::{
    Capacity, Infrastructure, Outcome, RECORD, Recorder, Terminal, Work, load, reseal,
};

use super::super::branch::{
    Facts, Milestone, Reached, Unbranched, custody, diverged, prefix_digest,
};
use super::super::bundle::{Stops, UploadState, admit, traced};
use super::super::replay::{Replayed, replay};
use super::super::scratch;
use super::{
    Census, Explored, LABEL, Leaf, Limits, Mode, Tree, TreePlant, explore, leaf_problems, spelled,
    walked,
};

/// The milestone the faulted upload's checks explore from.
const PENDING: &str = "pending-put";

/// A bundle of `profile` under the sample manifest, with `edit` applied to
/// its lines.
fn recorded_with(profile: &str, edit: &[(&str, &str)]) -> Vec<u8> {
    let platform = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let mut lines = crate::sim::manifest_tests::sample_lines(profile, &"a".repeat(64), &platform);
    for (key, value) in edit {
        lines
            .iter_mut()
            .find(|(known, _)| known == key)
            .expect("a schema key")
            .1 = (*value).to_owned();
    }
    let manifest = Manifest::parse(&crate::sim::manifest_tests::text(&lines)).expect("a manifest");
    traced(admit(&manifest).expect("an admitted manifest"), Vec::new()).sink
}

fn faulted_with(edit: &[(&str, &str)]) -> Vec<u8> {
    recorded_with("faulted", edit)
}

fn faulted() -> Vec<u8> {
    faulted_with(&[])
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    load(bytes, u64::MAX).expect("a bundle").digest
}

/// The sample limits.
const SAMPLE: Limits = Limits {
    depth: 2,
    children: 3,
    faults: 12,
    advances: 16,
};

/// Every report line kind parses to its fields, a node's class and cost
/// included, and any other line is kept unparsed rather than dropped.
#[test]
fn the_census_parses_every_line_kind_and_keeps_the_rest() {
    let hash = "ab".repeat(32);
    let uncounted = format!(
        "leaf 1 digest={hash} decisions=7 prefix={hash} semantic=5 candidates=3 bundle=leaf-1.bundle verdict=complete pass fired=03 required=03"
    );
    let lines = format!(
        "frontier root candidates=4 forked=3 unexplored=1\nchild 0 class=success code=- wall_us=10 cpu_us=8 max_rss_kib=900\nfrontier 0 candidates=2 forked=2 unexplored=0\nchild 0.1 class=watchdog wall_us=0 cpu_us=0 max_rss_kib=0\nchild 0.0 class=failed code=3 wall_us=1 cpu_us=1 max_rss_kib=1\nleaf 0.0 digest={hash} decisions=7 prefix={hash} semantic=5 candidates=3 bundle=leaf-0.0.bundle counts=true verdict=complete pass fired=03 required=03\nstray\nchild 1 class=success\n{uncounted}\n"
    );
    let census = Census::parse(&lines);
    assert_eq!(census.nodes.len(), 3);
    assert_eq!(census.nodes[1].class, "watchdog");
    assert_eq!(
        census
            .nodes
            .iter()
            .map(|node| node.code)
            .collect::<Vec<_>>(),
        [None, None, Some(3)]
    );
    assert_eq!(
        (census.nodes[0].cpu_us, census.nodes[0].max_rss_kib),
        (8, 900)
    );
    assert_eq!(
        census.leaves[0].verdict,
        "complete pass fired=03 required=03"
    );
    assert_eq!(census.leaves[0].unexplored(), 2);
    assert_eq!(census.frontiers.len(), 2);
    assert_eq!(census.frontiers[0].candidates, 4);
    assert_eq!(census.unexplored(), 3);
    assert_eq!(census.credited(), 1);
    assert_eq!(
        census.unparsed,
        ["stray", "child 1 class=success", &uncounted]
    );
    assert_eq!(spelled(&[]), "root");
    assert_eq!(spelled(&[0, 12]), "0.12");
}

/// A census fails, each by its own problem, for a lost node, named by path
/// with the prefix; a credited node that reported nothing; a branch point
/// whose counts miss its candidates or the nodes below it; a leaf past the
/// depth bound and one whose bundle is misnamed and missing; an unparsed
/// line; and a root that changed. A census with no leaf fails too. The report is
/// labelled composed-bounded and claims no exhaustion.
#[test]
fn every_census_fault_is_its_own_problem() {
    let (reached, _) = diverged(&faulted(), PENDING, None).unwrap();
    let hash = super::hex(&reached.prefix);
    let leaf = |path: &str| {
        format!(
            "leaf {path} digest={hash} decisions=7 prefix={hash} semantic={} candidates=1 bundle=absent-{path}.bundle counts=true verdict=complete pass fired=03 required=03\n",
            reached.semantic
        )
    };
    let lines = format!(
        "frontier root candidates=3 forked=3 unexplored=0\nchild 0 class=watchdog wall_us=0 cpu_us=0 max_rss_kib=0\nchild 1 class=success wall_us=5 cpu_us=5 max_rss_kib=5\nchild 2 class=success wall_us=5 cpu_us=5 max_rss_kib=5\nfrontier 2 candidates=3 forked=1 unexplored=1\nchild 2.0 class=success wall_us=5 cpu_us=5 max_rss_kib=5\n{}{}noise\n",
        leaf("2.0"),
        leaf("2.0.0"),
    );
    let explored = Explored {
        reached,
        limits: SAMPLE,
        parent: false,
        census: Census::parse(&lines),
    };
    let dir = std::env::temp_dir();
    let misnamed = |path: &str| {
        format!("leaf {path}: it reported bundle absent-{path}.bundle for leaf-{path}.bundle")
    };
    let missing = |path: &str| {
        format!("leaf {path}: its bundle cannot be read: No such file or directory (os error 2)")
    };
    let problems = explored.problems(&dir);
    assert_eq!(
        problems,
        [
            format!("lost 0 class=watchdog prefix={hash}: its subtree earns no credit"),
            "1 reported 0 leaves and frontiers".into(),
            "2 forked 1 of 3 candidates under a bound of 3, 1 unexplored, 1 reported".into(),
            misnamed("2.0"),
            missing("2.0"),
            "leaf 2.0.0 lies past the depth bound".into(),
            misnamed("2.0.0"),
            missing("2.0.0"),
            "unparsed: noise".into(),
            "the root's replay no longer reproduces the bundle".into(),
        ]
    );
    let (text, rendered) = explored.render(PENDING, &dir);
    assert_eq!(rendered, problems);
    assert!(explored.incomplete(&problems), "a leaf's bundle is missing");
    let count = problems.len();
    assert!(text.starts_with(&format!("label: {LABEL}\n")));
    assert!(!text.contains("exhaust"));
    assert!(text.ends_with(&format!("explore: {LABEL}, {count} problems\n")));
    let empty = Explored {
        census: Census::parse("frontier root candidates=0 forked=0 unexplored=0\n"),
        parent: true,
        ..explored
    };
    assert_eq!(empty.problems(&dir), ["the tree explored no leaf"]);
}

#[test]
fn a_pass_short_of_a_required_obligation_does_not_count() {
    let (reached, _) = diverged(&faulted(), PENDING, None).unwrap();
    let hash = super::hex(&reached.prefix);
    let leaf = |path: &str, counts: bool, fired: &str| {
        format!(
            "leaf {path} digest={hash} decisions=7 prefix={hash} semantic={} candidates=1 bundle=leaf-{path}.bundle counts={counts} verdict=complete pass fired={fired} required=03\n",
            reached.semantic
        )
    };
    let lines = format!(
        "frontier root candidates=2 forked=2 unexplored=0\nchild 0 class=success wall_us=5 cpu_us=5 max_rss_kib=5\nchild 1 class=success wall_us=5 cpu_us=5 max_rss_kib=5\n{}{}",
        leaf("0", true, "03"),
        leaf("1", false, "01"),
    );
    let explored = Explored {
        reached,
        limits: SAMPLE,
        parent: true,
        census: Census::parse(&lines),
    };
    assert!(explored.census.unparsed.is_empty(), "{explored:?}");
    assert!(!explored.passes());
    let (text, _) = explored.render(PENDING, &std::env::temp_dir());
    assert!(text.contains(" explored=2 failing=1 "), "{text}");
    assert!(
        text.contains("leaf: path=1 digest=") && text.contains(" counts=false verdict="),
        "{text}"
    );
}

#[test]
fn a_root_stopped_on_its_bounds_names_the_bound() {
    let (reached, _) = diverged(&faulted(), PENDING, None).unwrap();
    let explored = Explored {
        reached,
        limits: SAMPLE,
        parent: true,
        census: Census::parse("frontier root candidates=3 forked=0 unexplored=3\n"),
    };
    assert_eq!(
        explored.problems(&std::env::temp_dir()),
        [
            "the root passed its fault or advance bound before its first fork, at a choice of 3 candidates",
            "the tree explored no leaf",
        ]
    );
}

/// An in-process walk stands for the forked node at its path: it reaches
/// the milestone the prefix replay reaches, keeps the prefix's semantic
/// records, moves custody only with evidence, replays strictly from its
/// own tape, and gives one bundle per path and different bundles for
/// different paths.
#[test]
fn an_in_process_walk_keeps_the_prefix_and_replays_strictly() {
    let original = faulted();
    let (probe, _) = diverged(&original, PENDING, None).unwrap();
    let (reached, first) = walked(&original, PENDING, &[1, 0]).unwrap();
    let (_, again) = walked(&original, PENDING, &[1, 0]).unwrap();
    let (_, other) = walked(&original, PENDING, &[0, 0]).unwrap();
    assert_eq!(reached, probe);
    assert_eq!(digest(&first), digest(&again));
    assert_ne!(digest(&first), digest(&other));
    let pending = reached.facts.upload.unwrap();
    for bytes in [&first, &other] {
        assert_eq!(prefix_digest(bytes, reached.semantic), Some(reached.prefix));
        assert_eq!(
            custody(bytes, reached.semantic, Some(pending), false),
            Vec::<String>::new()
        );
        let (replayed, _) = replay(bytes).unwrap();
        assert_eq!(replayed, Replayed::Reproduced);
    }
}

#[test]
fn the_milestone_counts_decisions_at_its_admitting_boundary_with_a_draw_before_the_next_selection()
{
    let sites = crate::net::link::sites(0);
    let chooser = RefCell::new(Chooser::record(7, &sites));
    chooser.borrow_mut().launch(0);
    let candidate = |n: u8| {
        let mut bytes = [0; 16];
        bytes[0] = Domain::Workload as u8;
        bytes[15] = n;
        Candidate(bytes)
    };
    let draw = || {
        chooser
            .borrow_mut()
            .index(sites[0], 0, &[candidate(0), candidate(1)])
            .expect("a draw")
    };
    let capacity = Capacity::new(8, 4, 10_000, 4).unwrap();
    let mut recorder = Recorder::new(Vec::new(), capacity);
    // A bundle whose prefix is the fresh recorder's: its `Begin` record.
    let original = Recorder::new(Vec::new(), capacity)
        .finish(
            Terminal::Complete {
                outcome: Outcome::Pass,
                fired: 0,
                required: 0,
            },
            Work::default(),
        )
        .sink;
    let mut tree = Tree {
        milestone: Milestone::PendingPut,
        original: &original,
        diverged: false,
        root: 7,
        limits: SAMPLE,
        wait: Duration::from_secs(1),
        mode: Mode::Walk(Vec::new()),
        facts: Facts {
            boundary: 0,
            upload: Some(UploadState {
                attempt: 1,
                serial: 0,
                base: 0,
                grant: 1,
                held: 1,
                outcome: 0,
                bound: false,
            }),
            armed: false,
            ..Facts::default()
        },
        reached: None,
        refused: None,
        path: Vec::new(),
        faults: 0,
        advances: 0,
        report: None,
        children: Vec::new(),
        forked_at: None,
        candidates: None,
    };
    draw();
    let at_boundary = chooser.borrow().decisions();
    let mut stops = &mut tree;
    stops.stopped(&mut recorder, &chooser);
    draw();
    stops.select(&mut recorder, &[candidate(0)], &chooser);
    let reached = tree.reached.expect("the milestone");
    assert_eq!(reached.decisions, at_boundary);
    assert_eq!(reached.facts.boundary, 1);
}

/// A forked node whose recorder the cap closed stops branching and runs
/// on as a leaf, so its `infrastructure` terminal reaches the census the
/// way a cap after its bounds would; the root alone refuses the fork.
#[test]
fn a_forked_node_with_a_closed_recorder_runs_on_as_a_leaf() {
    let sites = crate::net::link::sites(0);
    let chooser = RefCell::new(Chooser::record(7, &sites));
    let candidate = |n: u8| {
        let mut bytes = [0; 16];
        bytes[0] = Domain::Workload as u8;
        bytes[15] = n;
        Candidate(bytes)
    };
    let mut capped = Recorder::new(Vec::new(), Capacity::new(8, 4, 64, 4).unwrap());
    for turn in 0..10_000u64 {
        capped.turn(turn, &[1; 16], turn, &[0; 12]);
    }
    capped.flush();
    assert!(!capped.flushed());
    let tree = |path: Vec<u16>| Tree {
        milestone: Milestone::PendingPut,
        original: &[],
        diverged: false,
        root: 7,
        limits: SAMPLE,
        wait: Duration::from_secs(1),
        mode: Mode::Fork(TreePlant::None),
        facts: Facts::default(),
        reached: Some(Reached {
            facts: Facts::default(),
            semantic: 0,
            prefix: [0; 32],
            decisions: 0,
        }),
        refused: None,
        path,
        faults: 0,
        advances: 0,
        report: None,
        children: Vec::new(),
        forked_at: None,
        candidates: None,
    };
    let runnable = [candidate(0), candidate(1)];
    let mut forked = tree(vec![0]);
    (&mut forked).select(&mut capped, &runnable, &chooser);
    assert_eq!(forked.refused, None);
    assert_eq!(forked.candidates, Some(2));
    let mut root = tree(Vec::new());
    (&mut root).select(&mut capped, &runnable, &chooser);
    assert_eq!(root.refused, Some(Refusal::Unflushed));
    assert_eq!(root.candidates, None);
}

/// A leaf whose run the record cap closed is credited and judged
/// `counts=false`, and its suffix is incomplete evidence, so the census
/// names it as a problem the way the branch form does. The bundle judged
/// is the one named for the leaf's path, whatever its report names, and
/// incompleteness is read from that bundle, whatever the report claims.
#[test]
fn an_infrastructure_leaf_is_a_problem() {
    let original = faulted();
    let (reached, bytes) = diverged(&original, PENDING, Some(0)).unwrap();
    let every = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let records = (bytes.len() / RECORD) as u64 - 16;
    let capped = reseal(&bytes, Capacity::new(8, 4, records, every).unwrap(), |_| {});
    let loaded = load(&capped, u64::MAX).unwrap();
    assert_eq!(
        loaded.terminal,
        Terminal::Infrastructure(Infrastructure::Cap)
    );
    let dir = scratch("sim-suffix-capped").unwrap();
    std::fs::write(dir.join("leaf-0.bundle"), &capped).unwrap();
    std::fs::write(dir.join("leaf-1.bundle"), &capped).unwrap();
    let hash = super::hex(&reached.prefix);
    let lines = format!(
        "frontier root candidates=2 forked=2 unexplored=0\nchild 0 class=success wall_us=5 cpu_us=5 max_rss_kib=5\nchild 1 class=success wall_us=5 cpu_us=5 max_rss_kib=5\nleaf 0 digest={} decisions={} prefix={hash} semantic={} candidates=1 bundle=leaf-0.bundle counts=false verdict=infrastructure cap\nleaf 1 digest={} decisions={} prefix={hash} semantic={} candidates=1 bundle=absent.bundle counts=true verdict=complete pass fired=03 required=03\n",
        super::hex(&loaded.digest),
        loaded.decisions,
        reached.semantic,
        super::hex(&loaded.digest),
        loaded.decisions,
        reached.semantic,
    );
    let explored = Explored {
        reached,
        limits: SAMPLE,
        parent: true,
        census: Census::parse(&lines),
    };
    let problems = explored.problems(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(explored.census.unparsed.is_empty(), "{explored:?}");
    assert!(!explored.passes());
    assert!(explored.incomplete(&problems), "{problems:?}");
    assert!(
        !explored.incomplete(&[]),
        "a leaf's claimed verdict alone decides nothing"
    );
    let of = |path: &str| -> Vec<&String> {
        problems
            .iter()
            .filter(|problem| problem.starts_with(&format!("leaf {path}:")))
            .collect()
    };
    let capped = of("0");
    assert_eq!(capped.len(), 1, "{problems:?}");
    assert!(capped[0].contains("infrastructure cap"), "{problems:?}");
    let claimed = of("1");
    assert!(
        claimed
            .iter()
            .any(|problem| problem.contains("reported bundle absent.bundle for leaf-1.bundle")),
        "{problems:?}"
    );
    assert!(
        claimed
            .iter()
            .any(|problem| problem.contains("infrastructure cap")),
        "{problems:?}"
    );
}

/// A tree is incomplete evidence when a node's host failed or killed it:
/// the parent lost its pipe or reap, the child could not set up its report,
/// it exited the host-failure code, or `SIGKILL` ended it. Every other
/// uncredited class is a complete result the census problems describe.
#[test]
fn a_tree_is_incomplete_only_when_a_nodes_host_failed() {
    let (reached, _) = diverged(&faulted(), PENDING, None).unwrap();
    let explored = |class: &str, code: &str| Explored {
        reached,
        limits: SAMPLE,
        parent: true,
        census: Census::parse(&format!(
            "frontier root candidates=1 forked=1 unexplored=0\nchild 0 class={class} code={code} wall_us=1 cpu_us=1 max_rss_kib=1\n"
        )),
    };
    for (class, code) in [
        ("lost", "-"),
        ("silent", &SETUP_FAILED.to_string()),
        ("failed", &HOST_FAILED.to_string()),
        ("signaled", &libc::SIGKILL.to_string()),
    ] {
        assert!(explored(class, code).incomplete(&[]), "{class} {code}");
    }
    for (class, code) in [
        ("failed", "101"),
        ("silent", "101"),
        ("watchdog", "-"),
        ("signaled", "15"),
        ("malformed", "0"),
        ("mismatch", "0"),
        ("success", "-"),
    ] {
        assert!(!explored(class, code).incomplete(&[]), "{class} {code}");
    }
}

/// Each manifest limit bounds the walk: one level of depth ends the path
/// after one selection; fault and advance bounds below the first choice's
/// counts leave the root a leaf, so a walk records what no walk records;
/// a child bound of one refuses the second candidate; and limits whose
/// widest tree passes the report bound are refused. Under the sample
/// limits the same walks branch.
#[test]
fn each_manifest_limit_bounds_the_tree() {
    let walk = |edit: &[(&str, &str)], path: &[u16]| {
        walked(&faulted_with(edit), PENDING, path).map(|(_, bytes)| digest(&bytes))
    };
    let deep = walk(&[], &[0, 0]).unwrap();
    assert_ne!(deep, walk(&[], &[0]).unwrap());
    let shallow = [("suffix_depth", "1")];
    assert_eq!(
        walk(&shallow, &[0, 0]).unwrap(),
        walk(&shallow, &[0]).unwrap()
    );
    let root = walk(&[], &[]).unwrap();
    assert_ne!(walk(&[], &[1]).unwrap(), root);
    for bound in [("suffix_faults", "1"), ("suffix_advances", "1")] {
        let unbranched = walk(&[bound], &[]).unwrap();
        assert_eq!(walk(&[bound], &[1]).unwrap(), unbranched, "{bound:?}");
    }
    let narrow = [("suffix_children", "1")];
    assert!(matches!(
        walk(&narrow, &[1]),
        Err(Unbranched::Milestone(Refusal::Host(_)))
    ));
    assert!(walk(&narrow, &[0]).is_ok());
    for limits in [
        [("suffix_depth", "8"), ("suffix_children", "3")],
        [("suffix_depth", "129"), ("suffix_children", "1")],
        [("suffix_depth", "123"), ("suffix_children", "1")],
    ] {
        assert!(
            matches!(walk(&limits, &[]), Err(Unbranched::Input(_))),
            "{limits:?}"
        );
    }
}

/// A library test explores only by walking: a fork from it is refused for
/// its threads, and the trees' worker cases fail under libtest.
#[test]
fn exploring_off_the_worker_is_refused() {
    let dir = std::env::temp_dir();
    let explored = explore(&faulted(), PENDING, &dir, TreePlant::None);
    assert!(
        matches!(explored, Err(Unbranched::Milestone(Refusal::Threads(count))) if count > 1),
        "{explored:?}"
    );
    for case in [
        composed_bounded_tree_accounts_every_leaf_and_frontier(),
        deeper_composed_bounded_trees_account_every_leaf_and_frontier(),
    ] {
        assert!(
            matches!(&case, Err(error) if error.contains("Threads")),
            "{case:?}"
        );
    }
}

/// Explores the pending-PUT milestone under the sample limits. Every node
/// is credited at a measured cost; every check passes and every leaf
/// passes; each leaf has the bundle its in-process walk records; the root
/// still reproduces the original. Planted nodes that hang, at either
/// level, panic or die earn no credit and are each the tree's one problem,
/// reported lost by path with the prefix. A tree from the planted
/// violation is complete, its failing leaves reported, and does not count.
pub(crate) fn composed_bounded_tree_accounts_every_leaf_and_frontier() -> Result<(), String> {
    let dir = scratch("sim-suffix")?;
    let checked = (|| {
        accounted(&faulted(), &dir.join("honest"), SAMPLE)?;
        planted(&dir)?;
        bounded(&dir)?;
        violating(&dir)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// Explores the pending-PUT milestone of `original`, whose manifest
/// declares `limits`, into `dir` and accounts the tree: every node is
/// credited at a measured cost, every check passes and every leaf passes,
/// each leaf has the bundle its in-process walk records, the root
/// reproduces the original, and it reached the milestone a probe reaches.
fn accounted(original: &[u8], dir: &Path, limits: Limits) -> Result<Explored, String> {
    std::fs::create_dir(dir).map_err(|error| error.to_string())?;
    let explored = explore(original, PENDING, dir, TreePlant::None)
        .map_err(|refused| format!("{refused:?}"))?;
    let problems = explored.problems(dir);
    let census = &explored.census;
    if !problems.is_empty() || !explored.passes() || explored.limits != limits {
        return Err(format!("{} leaves: {problems:?}", census.leaves.len()));
    }
    if census
        .nodes
        .iter()
        .any(|node| node.wall_us == 0 || node.cpu_us == 0 || node.max_rss_kib == 0)
    {
        return Err(format!("an unmeasured node: {:?}", census.nodes));
    }
    let (probe, _) = diverged(original, PENDING, None).map_err(|e| format!("{e:?}"))?;
    if probe != explored.reached {
        return Err(format!("{probe:?} against {:?}", explored.reached));
    }
    for leaf in &census.leaves {
        let path: Vec<u16> = leaf
            .path
            .split('.')
            .map(|index| index.parse().map_err(|_| leaf.path.clone()))
            .collect::<Result<_, _>>()?;
        let (_, bytes) =
            walked(original, PENDING, &path).map_err(|refused| format!("{refused:?}"))?;
        if digest(&bytes) != leaf.digest {
            return Err(format!("leaf {} forked and walked differ", leaf.path));
        }
    }
    Ok(explored)
}

/// The deeper trees the nightly worker case explores, each the sample
/// manifest with its depth and width edited: the sample width two levels
/// deeper, and the deepest two-way tree whose 128 leaves fit one report
/// frame.
pub(crate) const DEEPER: [Limits; 2] = [
    Limits { depth: 4, ..SAMPLE },
    Limits {
        depth: 7,
        children: 2,
        ..SAMPLE
    },
];

/// Explores each tree of [`DEEPER`] and accounts it as the sample tree is
/// accounted. Prints one line per tree, naming its limits, its node,
/// leaf and unexplored counts and its deepest leaf, then a closing line
/// once every tree completed within its bounds.
pub(crate) fn deeper_composed_bounded_trees_account_every_leaf_and_frontier() -> Result<(), String>
{
    let dir = scratch("sim-suffix-deeper")?;
    let checked = (|| {
        for limits in DEEPER {
            let (depth, children) = (limits.depth.to_string(), limits.children.to_string());
            let original =
                faulted_with(&[("suffix_depth", &depth), ("suffix_children", &children)]);
            let explored = accounted(&original, &dir.join(format!("depth-{depth}")), limits)?;
            let census = &explored.census;
            let deepest = census
                .leaves
                .iter()
                .map(|leaf| leaf.path.split('.').count())
                .max()
                .unwrap_or(0);
            println!(
                "deeper-suffix: depth={depth} children={children} faults={} advances={}: {} nodes credited, {} leaves walked alike, {} unexplored, deepest leaf {deepest}, 0 problems",
                limits.faults,
                limits.advances,
                census.nodes.len(),
                census.leaves.len(),
                census.unexplored()
            );
        }
        println!(
            "deeper-suffix: {} trees complete within their bounds, every leaf passing",
            DEEPER.len()
        );
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// Trees with one hanging, panicking or dying node under a two-second
/// watchdog: that node's loss is the only problem and its subtree reports
/// no leaf.
fn planted(dir: &Path) -> Result<(), String> {
    let original = faulted_with(&[("watchdog", "2")]);
    for (name, plant, path, class, incomplete) in [
        ("hang", TreePlant::Hang(&[1]), "1", "watchdog", false),
        (
            "deep-hang",
            TreePlant::Hang(&[0, 1]),
            "0.1",
            "watchdog",
            false,
        ),
        ("panic", TreePlant::Panic(&[0, 1]), "0.1", "failed", false),
        ("kill", TreePlant::Kill(&[0, 0]), "0.0", "signaled", true),
        (
            "unwritten",
            TreePlant::Unwritten(&[0, 1]),
            "0.1",
            "failed",
            true,
        ),
        ("refused", TreePlant::Refused(&[1]), "1", "failed", true),
    ] {
        let out = dir.join(name);
        std::fs::create_dir(&out).map_err(|error| error.to_string())?;
        let explored = explore(&original, PENDING, &out, plant)
            .map_err(|refused| format!("{name}: {refused:?}"))?;
        let lost = format!(
            "lost {path} class={class} prefix={}: its subtree earns no credit",
            super::hex(&explored.reached.prefix)
        );
        let problems = explored.problems(&out);
        if problems != [lost] || !explored.parent {
            return Err(format!("{name}: {problems:?}"));
        }
        if explored.incomplete(&problems) != incomplete {
            return Err(format!(
                "{name}: incomplete {}",
                explored.incomplete(&problems)
            ));
        }
        let node = explored.census.nodes.iter().find(|node| node.path == path);
        let host_code = if class == "signaled" {
            libc::SIGKILL
        } else {
            HOST_FAILED
        };
        if incomplete && node.is_none_or(|node| node.code != Some(host_code)) {
            return Err(format!(
                "{name}: {node:?} exited without the host-failure code"
            ));
        }
        let within = |leaf: &str| leaf == path || leaf.starts_with(&format!("{path}."));
        if explored.census.leaves.iter().any(|leaf| within(&leaf.path)) {
            return Err(format!("{name}: a lost node's subtree reported a leaf"));
        }
    }
    Ok(())
}

fn bounded(dir: &Path) -> Result<(), String> {
    for (name, bound) in [("faults", "suffix_faults"), ("advances", "suffix_advances")] {
        let out = dir.join(name);
        std::fs::create_dir(&out).map_err(|error| error.to_string())?;
        let explored = explore(
            &faulted_with(&[(bound, "1")]),
            PENDING,
            &out,
            TreePlant::None,
        )
        .map_err(|refused| format!("{name}: {refused:?}"))?;
        let census = &explored.census;
        let candidates = census.frontiers.first().map_or(0, |root| root.candidates);
        let expected = [
            format!(
                "the root passed its fault or advance bound before its first fork, at a choice of {candidates} candidates"
            ),
            "the tree explored no leaf".to_owned(),
        ];
        let problems = explored.problems(&out);
        if candidates < 2 || !census.nodes.is_empty() || problems != expected {
            return Err(format!("{name}: {problems:?} {census:?}"));
        }
    }
    Ok(())
}

/// The planted violation's tree: every node credited and every check
/// passing, with at least one leaf whose verdict is the violation.
fn violating(dir: &Path) -> Result<(), String> {
    let original = recorded_with("planted", &[]);
    let out = dir.join("violating");
    std::fs::create_dir(&out).map_err(|error| error.to_string())?;
    let explored = explore(&original, PENDING, &out, TreePlant::None)
        .map_err(|refused| format!("{refused:?}"))?;
    let problems = explored.problems(&out);
    let failing = explored
        .census
        .leaves
        .iter()
        .any(|leaf| leaf.verdict.starts_with("complete violation "));
    if !problems.is_empty() || !failing || explored.passes() {
        return Err(format!("{problems:?} {:?}", explored.census.leaves));
    }
    Ok(())
}

/// A leaf explored from `turn-0`, before any upload state, is judged for
/// its uploads' custody under its links' release mode. The honest leaves of
/// the faulted upload, on delayed links, and of `upload`, on links that
/// release at delivery, pass every check; the `upload` leaf judged as a
/// delayed link's fails, and the faulted leaf whose first suffix upload
/// state's attempt skips past attempt 1 fails custody.
#[test]
fn a_leaf_before_any_upload_is_judged_for_custody() {
    let upload = recorded_with("upload", &[]);
    let (delivered, at_delivery) = walked(&upload, "turn-0", &[0]).unwrap();
    assert!(delivered.facts.at_delivery && delivered.facts.upload.is_none());
    let delayed = custody(&at_delivery, delivered.semantic, None, false);
    assert!(
        !delayed.is_empty(),
        "the leaf's custody falls in the owner's poll"
    );
    let original = recorded_with("faulted", &[]);
    let (reached, bytes) = walked(&original, "turn-0", &[0]).unwrap();
    assert_eq!(reached.facts.upload, None);
    let dir = scratch("sim-unstarted-leaf").unwrap();
    let judged = |bytes: &[u8], reached: Reached| {
        std::fs::write(dir.join("leaf-0.bundle"), bytes).unwrap();
        let loaded = load(bytes, u64::MAX).unwrap();
        let leaf = Leaf {
            path: "0".into(),
            digest: loaded.digest,
            decisions: loaded.decisions,
            prefix: reached.prefix,
            semantic: reached.semantic,
            candidates: 1,
            bundle: "leaf-0.bundle".into(),
            counts: crate::sim::ledger::counts(&loaded),
            verdict: String::new(),
        };
        leaf_problems(&leaf, reached, &dir)
    };
    let delivered_problems = judged(&at_delivery, delivered);
    let honest = judged(&bytes, reached);
    let edited = super::super::branch::tests::with_changed_attempt(&bytes, reached.semantic);
    let changed = judged(&edited, reached);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(delivered_problems, Vec::<String>::new());
    assert_eq!(honest, Vec::<String>::new());
    let unexplained = super::super::branch::tests::attempt_unexplained(&changed, (0, 6));
    assert!(unexplained, "{changed:?}");
}

/// An exploration reaches a turn or script milestone where a branch's
/// prefix replay reaches it, in a mixed or a cluster run, and its
/// in-process walks keep that prefix and replay strictly from their own
/// tapes. Walks along different paths differ, except after h5-put's
/// `script-3`, whose every later draw has one candidate; a turn
/// milestone past the run's last boundary is refused for its predicate, as
/// a branch refuses it.
#[test]
fn walks_reach_turn_and_script_milestones_as_branches_do() {
    let c4 = recorded_with("c4", &[]);
    let h5 = recorded_with("h5-put", &[]);
    let cluster = recorded_with("cluster-broad", &[("root", "7")]);
    for (original, name, forced) in [
        (&c4, "turn-0", false),
        (&c4, "turn-1", false),
        (&c4, "script-5", false),
        (&h5, "script-3", true),
        (&cluster, "turn-1", false),
    ] {
        let (probe, _) = diverged(original, name, None).unwrap();
        let (reached, bytes) = walked(original, name, &[0]).unwrap();
        let (_, other) = walked(original, name, &[1]).unwrap();
        assert_eq!(reached, probe, "{name}");
        assert_eq!(digest(&bytes) == digest(&other), forced, "{name}");
        for bytes in [&bytes, &other] {
            assert_eq!(prefix_digest(bytes, reached.semantic), Some(reached.prefix));
            let (replayed, _) = replay(bytes).unwrap();
            assert_eq!(replayed, Replayed::Reproduced, "{name}");
        }
    }
    assert_eq!(
        walked(&c4, "turn-1000", &[]).map(|(reached, _)| reached),
        Err(Unbranched::Milestone(Refusal::Predicate))
    );
}
