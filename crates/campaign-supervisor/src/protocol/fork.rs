//! The forking forms' output: `--branch` and `--explore`.
//!
//! Both print the milestone where the run forked, its `witness:` line and
//! whether the parent still reproduced the bundle, or only `parent:
//! diverged before the milestone` when the prefix replay diverged, which
//! parses as `None`. The witness names the milestone line's milestone and
//! boundary and holds. A branch then prints each child, at most once per
//! suffix and sibling, each failed check and a tally; an exploration prints
//! its label
//! and limits, each node and leaf, each failed check, its frontier census
//! and a tally. A path is the dot-joined candidate indexes from the
//! unprinted root, counted from 0, each a canonical decimal `u16`. A child
//! prints a report only beside the success class; no two nodes or leaves
//! share a path, every leaf is a printed success node, every nested node's
//! parent is a printed success node, a leaf counts only beside a passing
//! verdict,
//! every tally agrees with the lines it counts, and the census's
//! unexplored total covers every leaf's unexplored candidates.

use crate::record::Digest;

use std::collections::HashSet;

use super::Error;
use super::pairs::{Pairs, count, counts, digest, fill, flag, owned, repeated, words};
use super::terminal::Terminal;

/// The value of the one `parent:` line a forking form prints when the
/// prefix replay diverged before the milestone.
const DIVERGED: &str = "diverged before the milestone";

/// The exploration label the worker prints.
pub const LABEL: &str = "composed-bounded";

/// Where a run reached its milestone: the stopped boundaries passed, the
/// prefix's semantic records and decisions, and the prefix's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Milestone {
    pub name: String,
    pub boundary: u64,
    pub semantic: u64,
    pub decisions: u64,
    pub prefix: Digest,
}

/// The facts at the boundary where the run forked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub milestone: String,
    /// Whether the milestone's predicate holds over these facts; the
    /// parser requires `true`.
    pub holds: bool,
    pub boundary: u64,
    /// The latest recorded `UPLOAD` state, or `None` when the prefix
    /// recorded none, which an upload that has begun can still leave.
    pub upload: Option<Upload>,
    /// Whether a planned recovery cut stands reached and not yet activated.
    pub armed: bool,
}

/// An upload's latest state at the witness boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upload {
    pub attempt: u64,
    pub grant: u64,
    /// The source slots a device holds for the upload.
    pub held: u64,
    /// The upload's result code, 0 while the result is undecided; a
    /// pending put holds only beside 0.
    pub outcome: u64,
}

words! {
    /// How a forked child ended, as its parent classifies it.
    ChildClass {
        /// A child that exited 0 with a success report; the only credited
        /// class.
        Success = "success",
        /// A child that exited nonzero with a failure report.
        Failed = "failed",
        /// A report whose verdict disagrees with the child's exit status.
        Mismatch = "mismatch",
        /// The child died from a signal.
        Signaled = "signaled",
        /// The child exited without writing a byte.
        Silent = "silent",
        /// The child wrote bytes that are not exactly one report.
        Malformed = "malformed",
        /// The child was still running at its deadline.
        Watchdog = "watchdog",
        /// The host failed to read or reap the child.
        Lost = "lost",
    }
}

/// The branch form's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
    pub milestone: Milestone,
    pub witness: Witness,
    pub reproduced: bool,
    pub children: Vec<Child>,
    pub problems: Vec<String>,
}

/// One forked child of a branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    /// The child's suffix, counted from 0; below the branch's requested
    /// suffix count.
    pub suffix: u64,
    /// The child's sibling within its suffix, counted from 0.
    pub sibling: u64,
    pub class: ChildClass,
    /// The digest and terminal of the child's bundle, when its report
    /// parsed.
    pub report: Option<(Digest, Terminal)>,
}

/// The exploration form's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explore {
    pub milestone: Milestone,
    pub witness: Witness,
    pub limits: Limits,
    pub reproduced: bool,
    pub nodes: Vec<Node>,
    pub leaves: Vec<Leaf>,
    pub problems: Vec<String>,
    /// Candidates left unforked anywhere in the tree.
    pub unexplored: u64,
}

/// An exploration tree's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub depth: u64,
    pub children: u64,
    pub faults: u64,
    pub advances: u64,
}

/// A forked node with its class and cost. A path is the dot-joined
/// candidate indexes from the unprinted root, each counted from 0. A node
/// its parent killed, at its deadline or after a failed read or reap,
/// reports zero wall time, CPU time and resident size, which measure
/// nothing; a node its own timer ended is reaped and reports what it cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub path: String,
    pub class: ChildClass,
    pub wall_us: u64,
    pub cpu_us: u64,
    pub max_rss_kib: i64,
}

/// A leaf of an exploration: the bundle at the end of one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub path: String,
    pub digest: Digest,
    /// Candidates left unforked at the leaf's first choice past its
    /// bounds.
    pub unexplored: u64,
    /// Whether the leaf's bundle counts; only beside a passing verdict.
    pub counts: bool,
    pub verdict: Terminal,
}

impl Branch {
    /// The branch output `text`, or `None` when the prefix replay diverged.
    ///
    /// # Errors
    ///
    /// [`Error::Torn`] for output cut short; [`Error::Unpaired`] for a
    /// line with no `": "`; [`Error::Missing`] for an absent once-printed
    /// line; [`Error::Repeated`] for a once-printed line or a child printed
    /// twice; [`Error::Unknown`] for a line of another key;
    /// [`Error::Value`] for a value outside its form; and
    /// [`Error::Inconsistent`] for a witness or tally that disagrees with
    /// the other lines.
    pub fn parse(text: &str) -> Result<Option<Self>, Error> {
        let Some(mut lines) = reached(text)? else {
            return Ok(None);
        };
        let (milestone, witness, reproduced) = milestone(&mut lines)?;
        let children = lines.all("child", child)?;
        let pairs: Vec<_> = children
            .iter()
            .map(|child| (child.suffix, child.sibling))
            .collect();
        if let Some((suffix, sibling)) = repeated(&pairs) {
            return Err(Error::Repeated(format!(
                "child suffix={suffix} sibling={sibling}"
            )));
        }
        let problems = problems(&mut lines)?;
        let credited = children
            .iter()
            .filter(|child| child.class == ChildClass::Success)
            .count();
        let tally = counts(
            lines.one("branch")?,
            "{} children, {} credited, {} problems",
            "branch",
        )?;
        let size = |items: usize| items as u64;
        if tally != [size(children.len()), size(credited), size(problems.len())] {
            return Err(Error::Inconsistent(
                "the branch tally disagrees with its lines",
            ));
        }
        lines.finish()?;
        Ok(Some(Self {
            milestone,
            witness,
            reproduced,
            children,
            problems,
        }))
    }
}

impl Explore {
    /// The exploration output `text`, or `None` when the prefix replay
    /// diverged.
    ///
    /// # Errors
    ///
    /// As [`Branch::parse`], with [`Error::Repeated`] for a node or leaf
    /// path printed twice and [`Error::Inconsistent`] for a leaf that names
    /// no printed node, a nested node whose parent is no printed success
    /// node, a leaf that counts beside a verdict that does not pass, or a
    /// census or tally that disagrees with the lines.
    pub fn parse(text: &str) -> Result<Option<Self>, Error> {
        let Some(mut lines) = reached(text)? else {
            return Ok(None);
        };
        if lines.one("label")? != LABEL {
            return Err(Error::Value("label"));
        }
        let (milestone, witness, reproduced) = milestone(&mut lines)?;
        let [depth, children, faults, advances] = counts(
            lines.one("limits")?,
            "depth={} children={} faults={} advances={}",
            "limits",
        )?;
        let limits = Limits {
            depth,
            children,
            faults,
            advances,
        };
        let (nodes, leaves) = (lines.all("node", node)?, lines.all("leaf", leaf)?);
        let paths: Vec<&str> = nodes.iter().map(|node| node.path.as_str()).collect();
        let ends: Vec<&str> = leaves.iter().map(|leaf| leaf.path.as_str()).collect();
        if let Some(path) = repeated(&paths) {
            return Err(Error::Repeated(format!("node path={path}")));
        }
        if let Some(path) = repeated(&ends) {
            return Err(Error::Repeated(format!("leaf path={path}")));
        }
        // Each forked node reports one leaf or one frontier in its success
        // report, so every leaf is a printed success node.
        let successes: HashSet<&str> = nodes
            .iter()
            .filter(|node| node.class == ChildClass::Success)
            .map(|node| node.path.as_str())
            .collect();
        if ends.iter().any(|end| !successes.contains(end)) {
            return Err(Error::Inconsistent("a leaf names no printed success node"));
        }
        if leaves
            .iter()
            .any(|leaf| leaf.counts && !leaf.verdict.passes())
        {
            return Err(Error::Inconsistent(
                "a leaf counts beside a verdict that does not pass",
            ));
        }
        let problems = problems(&mut lines)?;
        let [listed, credited, explored, failing, unexplored] = counts(
            lines.one("frontier")?,
            "nodes={} credited={} explored={} failing={} unexplored={}",
            "frontier",
        )?;
        let size = |items: usize| items as u64;
        let census = [
            size(nodes.len()),
            size(
                nodes
                    .iter()
                    .filter(|node| node.class == ChildClass::Success)
                    .count(),
            ),
            size(leaves.len()),
            size(leaves.iter().filter(|leaf| !leaf.counts).count()),
        ];
        // Interior frontiers add their own unforked candidates, so the
        // total covers the leaves' and may exceed them.
        let at_leaves = leaves
            .iter()
            .try_fold(0u64, |total, leaf| total.checked_add(leaf.unexplored));
        if [listed, credited, explored, failing] != census
            || at_leaves.is_none_or(|at_leaves| unexplored < at_leaves)
        {
            return Err(Error::Inconsistent(
                "the exploration census disagrees with its lines",
            ));
        }
        // A node's children print from its own success report; a first
        // index's parent is the unprinted root.
        if paths
            .iter()
            .filter_map(|path| path.rsplit_once('.'))
            .any(|(parent, _)| !successes.contains(parent))
        {
            return Err(Error::Inconsistent(
                "a node names no printed success node as its parent",
            ));
        }
        let [tallied] = counts(
            lines.one("explore")?,
            &format!("{LABEL}, {{}} problems"),
            "explore",
        )?;
        if tallied != size(problems.len()) {
            return Err(Error::Inconsistent(
                "the exploration tally disagrees with its problems",
            ));
        }
        lines.finish()?;
        Ok(Some(Self {
            milestone,
            witness,
            limits,
            reproduced,
            nodes,
            leaves,
            problems,
            unexplored,
        }))
    }
}

/// The lines of `text`, or `None` for output that is the divergence
/// line alone.
fn reached(text: &str) -> Result<Option<Pairs<'_>>, Error> {
    let mut lines = Pairs::lines(text)?;
    if !lines.every("parent").contains(&DIVERGED) {
        return Ok(Some(lines));
    }
    lines.one("parent")?;
    lines.finish()?;
    Ok(None)
}

fn problems(lines: &mut Pairs<'_>) -> Result<Vec<String>, Error> {
    lines.all("problem", owned)
}

/// The milestone, witness and parent lines both forms print.
fn milestone(lines: &mut Pairs<'_>) -> Result<(Milestone, Witness, bool), Error> {
    let pattern = "{} boundary={} semantic={} decisions={} prefix={}";
    let [name, boundary, semantic, decisions, prefix] =
        fill(lines.one("milestone")?, pattern, "milestone")?;
    let milestone = Milestone {
        name: owned(name, "milestone")?,
        boundary: count(boundary, "milestone")?,
        semantic: count(semantic, "milestone")?,
        decisions: count(decisions, "milestone")?,
        prefix: digest(prefix, "milestone")?,
    };
    let witness = lines.take("witness", witness)?;
    if (&witness.milestone, witness.boundary) != (&milestone.name, milestone.boundary) {
        return Err(Error::Inconsistent(
            "the witness names another milestone or boundary",
        ));
    }
    if !witness.holds {
        return Err(Error::Inconsistent(
            "the witness denies the milestone the run forked at",
        ));
    }
    let reproduced = match lines.one("parent")? {
        "reproduced" => true,
        "changed" => false,
        _ => return Err(Error::Value("parent")),
    };
    Ok((milestone, witness, reproduced))
}

fn witness(text: &str, key: &'static str) -> Result<Witness, Error> {
    let [name, holds, boundary, upload, armed] =
        fill(text, "{} holds={} boundary={} upload={} armed={}", key)?;
    let upload = match upload {
        "none" => None,
        state => {
            let [attempt, grant, held, outcome] =
                counts(state, "attempt:{},grant:{},held:{},outcome:{}", key)?;
            Some(Upload {
                attempt,
                grant,
                held,
                outcome,
            })
        }
    };
    Ok(Witness {
        milestone: owned(name, key)?,
        holds: flag(holds, key)?,
        boundary: count(boundary, key)?,
        upload,
        armed: flag(armed, key)?,
    })
}

/// A `child:` line, whose digest and terminal print only beside a parsed
/// report.
fn child(text: &str, key: &'static str) -> Result<Child, Error> {
    let (head, report) = match text.split_once(" digest=") {
        Some(_) => {
            let [head, hex, terminal] = fill(text, "{} digest={} terminal={}", key)?;
            (
                head,
                Some((digest(hex, key)?, Terminal::parse(terminal, key)?)),
            )
        }
        None => (text, None),
    };
    let [suffix, sibling, class] = fill(head, "suffix={} sibling={} class={}", key)?;
    let class = ChildClass::parse(class, key)?;
    // The parent reads a report only from a success frame.
    if report.is_some() && class != ChildClass::Success {
        return Err(Error::Inconsistent(
            "a child prints a report beside a class other than success",
        ));
    }
    Ok(Child {
        suffix: count(suffix, key)?,
        sibling: count(sibling, key)?,
        class,
        report,
    })
}

fn node(text: &str, key: &'static str) -> Result<Node, Error> {
    let pattern = "path={} class={} wall_us={} cpu_us={} max_rss_kib={}";
    let [path, class, wall_us, cpu_us, max_rss_kib] = fill(text, pattern, key)?;
    Ok(Node {
        path: tree_path(path, key)?,
        class: ChildClass::parse(class, key)?,
        wall_us: count(wall_us, key)?,
        cpu_us: count(cpu_us, key)?,
        max_rss_kib: i64::try_from(count(max_rss_kib, key)?).map_err(|_| Error::Value(key))?,
    })
}

fn leaf(text: &str, key: &'static str) -> Result<Leaf, Error> {
    let pattern = "path={} digest={} unexplored={} counts={} verdict={}";
    let [path, hex, unexplored, counts, verdict] = fill(text, pattern, key)?;
    Ok(Leaf {
        path: tree_path(path, key)?,
        digest: digest(hex, key)?,
        unexplored: count(unexplored, key)?,
        counts: flag(counts, key)?,
        verdict: Terminal::parse(verdict, key)?,
    })
}

/// A tree path: dot-joined candidate indexes from the unprinted root, each
/// a canonical decimal `u16`.
fn tree_path(text: &str, key: &'static str) -> Result<String, Error> {
    let index = |part: &str| count(part, key).is_ok_and(|index| u16::try_from(index).is_ok());
    text.split('.')
        .all(index)
        .then(|| text.to_owned())
        .ok_or(Error::Value(key))
}

/// Attributes a worker check to its branch child or exploration leaf.
pub(crate) fn child_check<'a>(problem: &'a str, label: &str) -> Option<&'a str> {
    problem.strip_prefix(label)
}

/// Identifies a check whose child lacks complete, readable evidence.
pub(crate) fn missing_child_evidence(check: &str) -> bool {
    [
        "its bundle cannot be read",
        "its bundle does not load",
        "its run left incomplete evidence",
    ]
    .iter()
    .any(|prefix| check.starts_with(prefix))
}
