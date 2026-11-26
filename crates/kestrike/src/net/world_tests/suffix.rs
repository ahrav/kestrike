//! Bounded suffix trees from a verified campaign prefix, explored through
//! forked children, with every leaf and frontier accounted. These are
//! composed bounded claims: each tree covers the selected suffixes of one
//! recorded prefix within the manifest's limits, and is never a claim that
//! an alphabet was exhausted.
//!
//! An exploration replays a bundle strictly to its milestone, admitted as a
//! branch's is: the first stopped boundary whose turns and events make the
//! milestone hold, with the prefix flushed, in the one-threaded worker. A
//! tree node branches at its first turn selection with more than one
//! runnable candidate, between turns, with the prefix and its suffix so far
//! flushed. The node forks one child for each runnable candidate, in
//! canonical order, up to the manifest's `suffix_children`; a child forces
//! its candidate as the selection and derives every later decision from a
//! root its path names, so the selection and the run after it replay
//! strictly from its tape.
//! Trees are enumerated without deduplication: two paths that reach one
//! state stay two nodes.
//!
//! A node stops branching once its path is `suffix_depth` selections long,
//! once the path since the milestone holds more than `suffix_faults`
//! link audit records or more than `suffix_advances` stopped boundaries,
//! or, below the root, once its recorder has closed.
//! A forked node that stops branching or whose run ends before another
//! choice is a leaf: it runs to its terminal, writes its bundle and reports
//! its verdict, digest, prefix, path, and whether its run counts under
//! [`ledger::counts`](crate::sim::ledger::counts): its terminal counts
//! and, for a recovery bundle, its campaign credits. Leaves are
//! forked nodes only. A root that passes its fault or advance bound before
//! its first fork fails its tree, and the census names that bound. A
//! node's unexplored frontier contains the remaining candidates at its
//! branch point and, for a leaf, the remaining candidates at its first
//! choice past its bounds; each branch point
//! reports its candidates, the children it forked and the rest.
//!
//! The root keeps replaying after it forks, so its bundle must still
//! reproduce the original. An interior node collects its children and
//! sends their reports up with its own frontier, then exits. Every parent
//! collects each child under the manifest's watchdog, counted from the
//! root's first fork and shortened per level so a node's children are
//! classified before its own parent's deadline. Only a success frame at
//! exit 0 read to end of file credits a child; a hung, interrupted, killed
//! or failed child, and a node that could not fork every child it chose,
//! is reported lost with its path and the prefix, and its subtree earns
//! nothing. A node below the root whose fork was refused also prints
//! `suffix fork PATH refused: REASON` on stderr, with the refusal's `Debug`
//! representation as `REASON`: its parent's census keeps only the failure
//! class, not that reason. A tree is complete when every node is credited,
//! every credited node reported a leaf or a frontier exactly once, every
//! branch point's counts reconcile with the bounds and the nodes below it,
//! it has a leaf, every leaf lies within the depth bound and its bundle
//! loads to its reported digest, starts with the prefix and keeps its
//! uploads' custody honest, and the root reproduced the original.
//! A complete tree counts only when every leaf's run counts.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::sim::choice::{Candidate, Chooser};
use crate::sim::fork::{self, Boundary, Classified, Report, Spawned, Verdict};
use crate::sim::manifest::Manifest;
use crate::sim::trace::{Recorder, Terminal, load};
use crate::sim::turn::Turn;

use super::branch::{
    Facts, Milestone, Ran, Reached, UNFINISHED, UNLOADED, UNREAD, Unbranched, custody, hex,
    milestone_lines, outcome, prefix_digest, replayed, terminal_text, unhex,
};
use super::bundle::{AUDIT, Stops};
use super::replay::recorded;

/// The label every exploration's report and case carries.
pub(crate) const LABEL: &str = "composed-bounded";

/// A tree's bounds, from the manifest before the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Selections along a path.
    pub(crate) depth: u64,
    /// Children one node forks.
    pub(crate) children: u64,
    /// Link audit records along a path since the milestone.
    pub(crate) faults: u64,
    /// Stopped boundaries along a path since the milestone.
    pub(crate) advances: u64,
}

impl Limits {
    pub(crate) fn of(manifest: &Manifest) -> Self {
        Self {
            depth: manifest.count("suffix_depth"),
            children: manifest.count("suffix_children"),
            faults: manifest.count("suffix_faults"),
            advances: manifest.count("suffix_advances"),
        }
    }
}

/// What the child at one path does besides its honest run, for the checks
/// that the tree credits only honest children.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TreePlant {
    None,
    /// Panics at its first turn selection.
    Panic(&'static [u16]),
    /// Sleeps forever at its first turn selection.
    Hang(&'static [u16]),
    /// Kills itself with `SIGKILL` at its first turn selection.
    Kill(&'static [u16]),
    /// Writes its leaf bundle into a directory that does not exist.
    Unwritten(&'static [u16]),
    /// Treats every fork at its branch point as refused by the host.
    Refused(&'static [u16]),
}

/// What an exploration does at its branch points.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    Fork(TreePlant),
    /// Takes these candidates in process, one per branch point, as the
    /// forked node at that path does while the path lasts.
    Walk(Vec<u16>),
}

/// A path as the reports spell it: `root`, or candidate indexes joined by
/// dots.
pub(crate) fn spelled(path: &[u16]) -> String {
    if path.is_empty() {
        return "root".into();
    }
    path.iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The root the child at `path` derives its later decisions from.
pub(crate) fn path_root(root: u64, path: &[u16]) -> u64 {
    let mut hash = Sha256::new()
        .chain_update(b"image-cache suffix tree v1")
        .chain_update(root.to_le_bytes());
    for index in path {
        hash.update(index.to_le_bytes());
    }
    u64::from_le_bytes(hash.finalize()[..8].try_into().expect("eight bytes"))
}

/// One exploring process's state across the stopped boundaries of its run.
#[derive(Debug)]
struct Tree<'b> {
    milestone: Milestone,
    /// The bundle under replay, whose prefix the replay's has to equal at
    /// the milestone before any child is forked.
    original: &'b [u8],
    /// The replay's records stopped matching the bundle's before any
    /// boundary held the milestone.
    diverged: bool,
    root: u64,
    limits: Limits,
    wait: Duration,
    mode: Mode,
    facts: Facts,
    reached: Option<Reached>,
    refused: Option<fork::Refusal>,
    /// This node's path; empty at the root.
    path: Vec<u16>,
    faults: u64,
    advances: u64,
    /// Set in a forked child: its end of the report pipe.
    report: Option<Report>,
    /// The root's children.
    children: Vec<(Vec<u16>, fork::Child)>,
    /// When the root forked its first child; every deadline counts from it.
    forked_at: Option<Instant>,
    /// The runnable candidates at this node's branch point, or at a
    /// leaf's first choice past its bounds; set once the node branched or
    /// stopped branching.
    candidates: Option<u64>,
}

impl Tree<'_> {
    /// The deadline by which the node at `level` classifies its children:
    /// each level below the root gets a shorter share of the watchdog. A
    /// child inherits `forked_at`, and a monotonic instant means the same
    /// time in every process, so every level counts from the root's first
    /// fork.
    #[expect(
        clippy::disallowed_methods,
        reason = "the child watchdog reads host time outside simulation decisions"
    )]
    fn deadline(&self, level: usize) -> Instant {
        let levels = self.limits.depth as u32 + 1;
        let share = self.wait * (levels - level as u32) / levels;
        self.forked_at.unwrap_or_else(Instant::now) + share
    }

    /// Whether this node may branch at its next point.
    fn within(&self) -> bool {
        (self.path.len() as u64) < self.limits.depth
            && self.faults <= self.limits.faults
            && self.advances <= self.limits.advances
    }

    /// Takes candidate `index` as this node's next selection: the path
    /// grows by it, every later decision derives from the path's root, and
    /// the selection itself is forced. A forked child and a walk enter a
    /// path the same way, so both record the same bundle.
    fn enter(&mut self, index: u16, chooser: &RefCell<Chooser>) {
        self.path.push(index);
        let mut chooser = chooser.borrow_mut();
        chooser.diverge(path_root(self.root, &self.path));
        chooser.force(index.into());
    }

    /// Forks one child per candidate, up to the child bound; a child
    /// returns at once on its path. The root returns to its replay; an
    /// interior node collects its children, reports and exits, with a
    /// failure frame when a fork failed. That node also prints
    /// `suffix fork PATH refused: REASON` on stderr, with the refusal's
    /// `Debug` representation as `REASON`.
    fn fork(&mut self, runnable: &[Candidate], chooser: &RefCell<Chooser>) {
        let taken = runnable.len().min(self.limits.children as usize);
        self.candidates = Some(runnable.len() as u64);
        #[expect(
            clippy::disallowed_methods,
            reason = "the child watchdog reads host time outside simulation decisions"
        )]
        self.forked_at.get_or_insert_with(Instant::now);
        // Each child's own timer ends it at the deadline its parent
        // collects it by.
        let deadline = self.deadline(self.path.len());
        let mut children = Vec::new();
        if let Mode::Fork(TreePlant::Refused(path)) = &self.mode
            && self.report.is_some()
            && self.path == *path
        {
            self.refused = Some(fork::Refusal::Host("a planted refusal".into()));
        }
        for index in 0..taken as u16 {
            if self.refused.is_some() {
                break;
            }
            // SAFETY: the child forgets its earlier siblings' handles and its
            // parent's report below, holds no other inherited descriptor
            // owner, and ends through `fork::exit` in `fork` or
            // `finish_node`; `explore` catches a panic in its run into
            // `finish_node`.
            match unsafe { fork::spawn(deadline) } {
                Ok(Spawned::Parent(child)) => {
                    let mut path = self.path.clone();
                    path.push(index);
                    children.push((path, child));
                }
                Ok(Spawned::Child(report)) => {
                    std::mem::forget(children);
                    std::mem::forget(std::mem::take(&mut self.children));
                    // The parent's report stood at the descriptor this
                    // child's report replaced; dropping it would close
                    // this child's own.
                    std::mem::forget(self.report.replace(report));
                    self.candidates = None;
                    self.enter(index, chooser);
                    return;
                }
                Err(error) => {
                    self.refused = Some(fork::Refusal::Host(error));
                    break;
                }
            }
        }
        if self.report.is_none() {
            self.children = children;
            return;
        }
        if let Some(refused) = &self.refused {
            let _ = writeln!(
                std::io::stderr(),
                "suffix fork {} refused: {refused:?}",
                spelled(&self.path)
            );
        }
        let forked = children.len() as u64;
        let lines = frontier_report(
            &self.path,
            (runnable.len() as u64, forked),
            children,
            deadline,
        );
        let verdict = if self.refused.is_some() {
            Verdict::Failure
        } else {
            Verdict::Success
        };
        let sent = self
            .report
            .as_mut()
            .is_some_and(|report| report.send(verdict, lines.as_bytes()));
        fork::exit(match (sent, &self.refused) {
            (true, None) => 0,
            (_, Some(fork::Refusal::Host(_))) => fork::HOST_FAILED,
            _ => 101,
        });
    }

    /// Acts on this node's plant at its first turn selection.
    fn plant(&self) {
        let Mode::Fork(plant) = self.mode else {
            return;
        };
        let at = |path: &[u16]| self.report.is_some() && self.path == path;
        match plant {
            TreePlant::Panic(path) if at(path) => panic!("a planted panic in a tree node"),
            TreePlant::Hang(path) if at(path) => loop {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "the watchdog fixture parks a forked child outside the simulated schedule"
                )]
                std::thread::sleep(Duration::from_secs(1));
            },
            TreePlant::Kill(path) if at(path) => {
                // SAFETY: `raise` takes a plain signal number.
                unsafe { libc::raise(libc::SIGKILL) };
            }
            _ => {}
        }
    }
}

/// A node's report: its frontier line, its `(candidates, forked)` counts,
/// then, for each child collected at once by `deadline`, its class line
/// and, when it is credited, the lines it sent.
fn frontier_report(
    path: &[u16],
    (candidates, forked): (u64, u64),
    children: Vec<(Vec<u16>, fork::Child)>,
    deadline: Instant,
) -> String {
    let mut out = format!(
        "frontier {} candidates={candidates} forked={forked} unexplored={}\n",
        spelled(path),
        candidates - forked
    );
    let (paths, processes): (Vec<_>, Vec<_>) = children.into_iter().unzip();
    for (path, (class, usage)) in paths.iter().zip(fork::collect_all(processes, deadline)) {
        let code = match &class {
            Classified::Failed { code, .. }
            | Classified::Mismatch { code, .. }
            | Classified::Silent(code)
            | Classified::Malformed(code)
            | Classified::Signaled(code) => code.to_string(),
            Classified::Success(_) | Classified::Watchdog | Classified::Lost(_) => "-".into(),
        };
        let _ = writeln!(
            out,
            "child {} class={} code={code} wall_us={} cpu_us={} max_rss_kib={}",
            spelled(path),
            class.name(),
            usage.wall.as_micros(),
            usage.cpu.as_micros(),
            usage.max_rss_kib
        );
        if let Classified::Success(payload) = &class {
            out.push_str(&String::from_utf8_lossy(payload));
        }
    }
    out
}

impl<W: Write> Stops<W> for &mut Tree<'_> {
    fn events(&mut self, events: &[crate::sim::trace::Event]) {
        if self.reached.is_some() {
            self.faults += events.iter().filter(|event| event.kind == AUDIT).count() as u64;
        } else {
            self.facts.events(events);
        }
    }

    fn turn(&mut self, turn: &Turn) {
        self.facts.turned(turn);
    }

    fn stopped(&mut self, recorder: &mut Recorder<W>, chooser: &RefCell<Chooser>) {
        self.facts.boundary += 1;
        if self.reached.is_some() {
            self.advances += 1;
            return;
        }
        if self.refused.is_some() || self.diverged || !self.milestone.holds(&self.facts) {
            return;
        }
        recorder.flush();
        // The milestone's facts came from the replay's own records; the
        // children continue the bundle only if those records are the
        // bundle's.
        let (semantic, prefix) = recorder.prefix();
        if prefix_digest(self.original, semantic) != Some(prefix) {
            self.diverged = true;
            return;
        }
        if let Mode::Fork(_) = self.mode {
            let boundary = Boundary {
                stopped: true,
                holds: true,
                flushed: recorder.flushed(),
            };
            if let Err(refusal) = fork::eligible(boundary) {
                self.refused = Some(refusal);
                return;
            }
        }
        self.reached = Some(Reached {
            facts: self.facts,
            semantic,
            prefix,
            decisions: chooser.borrow().decisions(),
        });
    }

    fn select(
        &mut self,
        recorder: &mut Recorder<W>,
        runnable: &[Candidate],
        chooser: &RefCell<Chooser>,
    ) {
        if self.reached.is_none() {
            return;
        }
        self.plant();
        // A node that recorded its candidates has branched or stopped
        // branching; it takes every later selection from its chooser.
        if runnable.len() < 2 || self.refused.is_some() || self.candidates.is_some() {
            return;
        }
        if !self.within() {
            self.candidates = Some(runnable.len() as u64);
            return;
        }
        match &self.mode {
            Mode::Fork(_) => {
                recorder.flush();
                if !recorder.flushed() {
                    // A forked node's closed recorder ends its run in an
                    // infrastructure terminal the census reads from its
                    // leaf; the root reports the refusal itself.
                    if self.path.is_empty() {
                        self.refused = Some(fork::Refusal::Unflushed);
                    } else {
                        self.candidates = Some(runnable.len() as u64);
                    }
                    return;
                }
                self.fork(runnable, chooser);
            }
            Mode::Walk(walk) => {
                let Some(&index) = walk.get(self.path.len()) else {
                    self.candidates = Some(runnable.len() as u64);
                    return;
                };
                if usize::from(index) >= runnable.len().min(self.limits.children as usize) {
                    self.refused = Some(fork::Refusal::Host(format!(
                        "the walk names candidate {index} of {}",
                        runnable.len()
                    )));
                    return;
                }
                self.enter(index, chooser);
            }
        }
    }
}

/// A leaf's report line; its verdict comes last because it holds spaces.
fn leaf_line(tree: &Tree<'_>, bytes: &[u8], name: &str) -> String {
    let reached = tree.reached.expect("a leaf runs past its milestone");
    match load(bytes, u64::MAX) {
        Ok(loaded) => format!(
            "leaf {} digest={} decisions={} prefix={} semantic={} candidates={} bundle={name} counts={} verdict={}\n",
            spelled(&tree.path),
            hex(&loaded.digest),
            loaded.decisions,
            hex(&reached.prefix),
            reached.semantic,
            tree.candidates.unwrap_or(0),
            crate::sim::ledger::counts(&loaded),
            terminal_text(loaded.terminal),
        ),
        Err(error) => format!("unloadable {} {error:?}\n", spelled(&tree.path)),
    }
}

/// Ends a forked tree node whose run returned: a leaf writes its bundle
/// into `dir` and reports it; a node whose run panicked reports that. A
/// panic while it reports ends it with exit code 101 as well.
fn finish_node(tree: &mut Tree<'_>, ran: std::thread::Result<Vec<u8>>, dir: &Path) -> ! {
    let Some(mut report) = tree.report.take() else {
        fork::exit(101);
    };
    let mut unwritten = false;
    let sent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Ok(bytes) = ran else {
            report.send(Verdict::Failure, b"panicked\n");
            return false;
        };
        if let Some(refused) = &tree.refused {
            report.send(
                Verdict::Failure,
                format!("refused: {refused:?}\n").as_bytes(),
            );
            return false;
        }
        let name = format!("leaf-{}.bundle", spelled(&tree.path));
        let dir = match tree.mode {
            Mode::Fork(TreePlant::Unwritten(path)) if tree.path == path => dir.join("absent"),
            _ => dir.to_path_buf(),
        };
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(&name))
            .and_then(|mut file| file.write_all(&bytes).and_then(|()| file.flush()));
        match written {
            Ok(()) => report.send(Verdict::Success, leaf_line(tree, &bytes, &name).as_bytes()),
            Err(error) => {
                report.send(Verdict::Failure, format!("unwritten: {error}\n").as_bytes());
                unwritten = true;
                false
            }
        }
    }));
    fork::exit(match (sent.unwrap_or(false), unwritten) {
        (true, _) => 0,
        (false, true) => fork::HOST_FAILED,
        (false, false) => 101,
    });
}

/// The most leaves, and levels, a tree's limits allow: each leaf's line
/// must fit, with its parents', in one report frame. The manifest keeps
/// every count above zero.
const MAX_LEAVES: u64 = 128;

fn longest_leaf_name(limits: &Limits) -> usize {
    let depth = limits.depth as usize;
    let index = (limits.children - 1).to_string().len();
    "leaf-".len() + depth * index + depth.saturating_sub(1) + ".bundle".len()
}

/// An exploring replay of `original` under `mode`: the tree's state and
/// its run.
///
/// # Errors
///
/// As [`replayed`], and `Input` for limits whose widest tree exceeds
/// [`MAX_LEAVES`] or whose longest leaf bundle name exceeds `libc::NAME_MAX`
/// bytes.
fn explored<'b>(original: &'b [u8], name: &str, mode: Mode) -> Result<(Tree<'b>, Ran), Unbranched> {
    let (_, manifest) =
        recorded(original).map_err(|refused| Unbranched::Input(format!("{refused:?}")))?;
    let limits = Limits::of(&manifest);
    let widest = u32::try_from(limits.depth)
        .ok()
        .and_then(|depth| limits.children.checked_pow(depth));
    if limits.depth > MAX_LEAVES || widest.is_none_or(|leaves| leaves > MAX_LEAVES) {
        return Err(Unbranched::Input(format!(
            "{limits:?} allow more than {MAX_LEAVES} leaves or levels"
        )));
    }
    if longest_leaf_name(&limits) > libc::NAME_MAX as usize {
        return Err(Unbranched::Input(format!(
            "{limits:?} name a leaf bundle longer than {} bytes",
            libc::NAME_MAX
        )));
    }
    replayed(original, name, |milestone, manifest, facts| Tree {
        milestone,
        original,
        diverged: false,
        root: manifest.root,
        limits,
        wait: Duration::from_secs(manifest.count("watchdog")),
        mode,
        facts,
        reached: None,
        refused: None,
        path: Vec::new(),
        faults: 0,
        advances: 0,
        report: None,
        children: Vec::new(),
        forked_at: None,
        candidates: None,
    })
}

/// Replays `original` to milestone `name` and walks `path` in process, one
/// candidate per branch point, as the forked node at that path does while
/// the path lasts: the milestone and the bundle the walk records. Past the
/// path's end, or past the tree's bounds, the walk runs on as the leaf it
/// reached.
///
/// # Errors
///
/// As [`Unbranched`], and `Milestone(Host)` for a path that names a
/// candidate a branch point lacks.
pub(crate) fn walked(
    original: &[u8],
    name: &str,
    path: &[u16],
) -> Result<(Reached, Vec<u8>), Unbranched> {
    let (tree, ran) = explored(original, name, Mode::Walk(path.to_vec()))?;
    let (bytes, reproduced) = ran.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    Ok((
        outcome(tree.reached, &tree.refused, reproduced && !tree.diverged)?,
        bytes,
    ))
}

/// One node the census reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) path: String,
    pub(crate) class: String,
    /// The exit code or signal behind the class, when it has one.
    pub(crate) code: Option<i32>,
    pub(crate) wall_us: u64,
    pub(crate) cpu_us: u64,
    pub(crate) max_rss_kib: i64,
}

impl Node {
    pub(crate) fn credited(&self) -> bool {
        self.class == Classified::Success(Vec::new()).name()
    }

    /// Whether the node's host failed or killed it, so its subtree has no
    /// evidence either way: the parent lost its pipe or reap, the child
    /// could not set up its report, it ended with [`fork::HOST_FAILED`], or
    /// `SIGKILL` ended it. The tree's own kills end as `Watchdog` or `Lost`
    /// and a node's timer raises `SIGALRM`, so a `SIGKILL` death is the
    /// host's, as the branch form reads the same child.
    pub(crate) fn host_failed(&self) -> bool {
        let named = |class: &Classified| self.class == class.name();
        named(&Classified::Lost(String::new()))
            || (named(&Classified::Silent(0)) && self.code == Some(fork::SETUP_FAILED))
            || (named(&Classified::Failed {
                code: 0,
                payload: Vec::new(),
            }) && self.code == Some(fork::HOST_FAILED))
            || (named(&Classified::Signaled(0)) && self.code == Some(libc::SIGKILL))
    }
}

/// One interior node's branch point: its runnable candidates, the
/// children it forked and the rest, unexplored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Frontier {
    pub(crate) path: String,
    pub(crate) candidates: u64,
    pub(crate) forked: u64,
    pub(crate) unexplored: u64,
}

/// One leaf the census reports, with the candidates at its first choice
/// past its bounds, all but the one it took unexplored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Leaf {
    pub(crate) path: String,
    pub(crate) digest: [u8; 32],
    pub(crate) decisions: u64,
    pub(crate) prefix: [u8; 32],
    pub(crate) semantic: u64,
    pub(crate) candidates: u64,
    pub(crate) bundle: String,
    /// [`ledger::counts`](crate::sim::ledger::counts) of the leaf's bundle:
    /// a pass whose every required obligation fired and, for a recovery
    /// bundle, a credited campaign.
    pub(crate) counts: bool,
    pub(crate) verdict: String,
}

impl Leaf {
    pub(crate) fn unexplored(&self) -> u64 {
        self.candidates.saturating_sub(1)
    }
}

/// A tree's census: every forked node with its class and cost, every
/// interior node's branch point, every leaf, and every line that did not
/// parse.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Census {
    pub(crate) nodes: Vec<Node>,
    pub(crate) frontiers: Vec<Frontier>,
    pub(crate) leaves: Vec<Leaf>,
    pub(crate) unparsed: Vec<String>,
}

/// The `key=value` fields of `words`.
fn fields<'a>(
    words: impl Iterator<Item = &'a str>,
) -> std::collections::BTreeMap<&'a str, &'a str> {
    words.filter_map(|word| word.split_once('=')).collect()
}

/// The count field `key` of `found`.
fn count(found: &std::collections::BTreeMap<&str, &str>, key: &str) -> Option<u64> {
    found.get(key)?.parse().ok()
}

impl Census {
    /// The census `lines` spell, the report lines of the root and every
    /// credited node below it.
    pub(crate) fn parse(lines: &str) -> Self {
        let mut census = Self::default();
        for line in lines.lines() {
            if census.take(line).is_none() {
                census.unparsed.push(line.to_owned());
            }
        }
        census
    }

    fn take(&mut self, line: &str) -> Option<()> {
        let mut words = line.split(' ');
        let (kind, path) = (words.next()?, words.next()?.to_owned());
        match kind {
            "child" => {
                let found = fields(words);
                self.nodes.push(Node {
                    path,
                    class: (*found.get("class")?).to_owned(),
                    code: found.get("code").and_then(|code| code.parse().ok()),
                    wall_us: count(&found, "wall_us")?,
                    cpu_us: count(&found, "cpu_us")?,
                    max_rss_kib: found.get("max_rss_kib")?.parse().ok()?,
                });
            }
            "frontier" => {
                let found = fields(words);
                self.frontiers.push(Frontier {
                    path,
                    candidates: count(&found, "candidates")?,
                    forked: count(&found, "forked")?,
                    unexplored: count(&found, "unexplored")?,
                });
            }
            "leaf" => {
                let (head, verdict) = line.split_once(" verdict=")?;
                let found = fields(head.split(' ').skip(2));
                self.leaves.push(Leaf {
                    path,
                    digest: unhex(found.get("digest")?)?,
                    decisions: count(&found, "decisions")?,
                    prefix: unhex(found.get("prefix")?)?,
                    semantic: count(&found, "semantic")?,
                    candidates: count(&found, "candidates")?,
                    bundle: (*found.get("bundle")?).to_owned(),
                    counts: found.get("counts")?.parse().ok()?,
                    verdict: verdict.to_owned(),
                });
            }
            _ => return None,
        }
        Some(())
    }

    /// Collected nodes that earned credit.
    pub(crate) fn credited(&self) -> usize {
        self.nodes.iter().filter(|node| node.credited()).count()
    }

    /// Candidates left unforked anywhere in the tree.
    pub(crate) fn unexplored(&self) -> u64 {
        self.frontiers
            .iter()
            .map(|frontier| frontier.unexplored)
            .sum::<u64>()
            + self.leaves.iter().map(Leaf::unexplored).sum::<u64>()
    }
}

/// The path of the node that forked the node at `path`.
fn parent(path: &str) -> &str {
    path.rsplit_once('.').map_or("root", |(head, _)| head)
}

/// An explored bundle: its milestone and limits, whether the root's replay
/// still reproduced the original, and the census.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Explored {
    pub(crate) reached: Reached,
    pub(crate) limits: Limits,
    pub(crate) parent: bool,
    pub(crate) census: Census,
}

impl Explored {
    /// Every failed check:
    ///
    /// - a lost node, with its path and the prefix;
    /// - a credited node that reported no leaf or frontier, or two;
    /// - a branch point whose forked and unexplored counts miss its
    ///   candidates, that forked past the child bound or below it while
    ///   leaving candidates unexplored, or whose forked count differs from
    ///   the nodes reported below it;
    /// - a root that passed its fault or advance bound before its first
    ///   fork, which records its candidates with a fork count of zero;
    /// - a leaf deeper than the depth bound, or whose prefix, bundle or
    ///   custody fails, its bundle read from `dir`;
    /// - a tree with no leaf, an unparsed line, and a root that no longer
    ///   reproduces.
    pub(crate) fn problems(&self, dir: &Path) -> Vec<String> {
        let census = &self.census;
        let prefix = hex(&self.reached.prefix);
        let mut out = Vec::new();
        for node in &census.nodes {
            if !node.credited() {
                out.push(format!(
                    "lost {} class={} prefix={prefix}: its subtree earns no credit",
                    node.path, node.class
                ));
                continue;
            }
            let reports = census
                .leaves
                .iter()
                .filter(|leaf| leaf.path == node.path)
                .count()
                + census
                    .frontiers
                    .iter()
                    .filter(|frontier| frontier.path == node.path)
                    .count();
            if reports != 1 {
                out.push(format!(
                    "{} reported {reports} leaves and frontiers",
                    node.path
                ));
            }
        }
        for frontier in &census.frontiers {
            if frontier.path == "root" && frontier.forked == 0 && frontier.candidates > 0 {
                out.push(format!(
                    "the root passed its fault or advance bound before its first fork, at a choice of {} candidates",
                    frontier.candidates
                ));
                continue;
            }
            let below = census
                .nodes
                .iter()
                .filter(|node| parent(&node.path) == frontier.path)
                .count() as u64;
            let bound = self.limits.children;
            if frontier.forked + frontier.unexplored != frontier.candidates
                || frontier.forked != frontier.candidates.min(bound)
                || frontier.forked != below
            {
                out.push(format!(
                    "{} forked {} of {} candidates under a bound of {bound}, {} unexplored, {below} reported",
                    frontier.path, frontier.forked, frontier.candidates, frontier.unexplored
                ));
            }
        }
        for leaf in &census.leaves {
            if leaf.path.split('.').count() as u64 > self.limits.depth {
                out.push(format!("leaf {} lies past the depth bound", leaf.path));
            }
            out.extend(
                leaf_problems(leaf, self.reached, dir)
                    .into_iter()
                    .map(|problem| format!("leaf {}: {problem}", leaf.path)),
            );
        }
        if census.leaves.is_empty() {
            out.push("the tree explored no leaf".into());
        }
        for line in &census.unparsed {
            out.push(format!("unparsed: {line}"));
        }
        if !self.parent {
            out.push("the root's replay no longer reproduces the bundle".into());
        }
        out
    }

    pub(crate) fn passes(&self) -> bool {
        self.census.leaves.iter().all(|leaf| leaf.counts)
    }

    /// Whether a node's host failed, a leaf's bundle could not be read or
    /// loaded, or a leaf's loaded bundle ended in an infrastructure class,
    /// so the tree is incomplete evidence, as the branch form reads the
    /// same child. `problems` are this tree's, from
    /// [`problems`](Self::problems); the parent-side cases are read from the
    /// bundle there, whatever the leaf's report claimed.
    pub(crate) fn incomplete(&self, problems: &[String]) -> bool {
        self.census.nodes.iter().any(Node::host_failed)
            || problems.iter().any(|problem| {
                [UNREAD, UNLOADED, UNFINISHED]
                    .iter()
                    .any(|prefix| problem.contains(&format!(": {prefix}")))
            })
    }

    /// The report lines the worker prints, problems included, and the
    /// failed checks themselves.
    pub(crate) fn render(&self, name: &str, dir: &Path) -> (String, Vec<String>) {
        let (reached, limits, census) = (&self.reached, &self.limits, &self.census);
        let mut out = format!(
            "label: {LABEL}\n{}limits: depth={} children={} faults={} advances={}\nparent: {}\n",
            milestone_lines(name, reached),
            limits.depth,
            limits.children,
            limits.faults,
            limits.advances,
            if self.parent { "reproduced" } else { "changed" },
        );
        for node in &census.nodes {
            let _ = writeln!(
                out,
                "node: path={} class={} wall_us={} cpu_us={} max_rss_kib={}",
                node.path, node.class, node.wall_us, node.cpu_us, node.max_rss_kib
            );
        }
        for leaf in &census.leaves {
            let _ = writeln!(
                out,
                "leaf: path={} digest={} unexplored={} counts={} verdict={}",
                leaf.path,
                hex(&leaf.digest),
                leaf.unexplored(),
                leaf.counts,
                leaf.verdict
            );
        }
        let problems = self.problems(dir);
        for problem in &problems {
            let _ = writeln!(out, "problem: {problem}");
        }
        let failing = census.leaves.iter().filter(|leaf| !leaf.counts).count();
        let _ = writeln!(
            out,
            "frontier: nodes={} credited={} explored={} failing={failing} unexplored={}",
            census.nodes.len(),
            census.credited(),
            census.leaves.len(),
            census.unexplored()
        );
        let _ = writeln!(out, "explore: {LABEL}, {} problems", problems.len());
        (out, problems)
    }
}

/// The checks one leaf fails against the milestone.
fn leaf_problems(leaf: &Leaf, reached: Reached, dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if (leaf.prefix, leaf.semantic) != (reached.prefix, reached.semantic) {
        out.push("its prefix differs from the root's".into());
    }
    let name = format!("leaf-{}.bundle", leaf.path);
    if leaf.bundle != name {
        out.push(format!("it reported bundle {} for {name}", leaf.bundle));
    }
    let bytes = match std::fs::read(dir.join(&name)) {
        Ok(bytes) => bytes,
        Err(error) => {
            out.push(format!("{UNREAD}: {error}"));
            return out;
        }
    };
    match load(&bytes, u64::MAX) {
        Ok(loaded) if (loaded.digest, loaded.decisions) == (leaf.digest, leaf.decisions) => {
            if crate::sim::ledger::counts(&loaded) != leaf.counts {
                out.push(format!(
                    "its bundle counts {} and its report says {}",
                    crate::sim::ledger::counts(&loaded),
                    leaf.counts
                ));
            }
            if let Terminal::Infrastructure(_) = loaded.terminal {
                out.push(format!(
                    "{UNFINISHED}: its bundle ends in {}",
                    terminal_text(loaded.terminal)
                ));
            }
        }
        Ok(loaded) => out.push(format!(
            "its bundle loads as digest {} with {} decisions, against its report",
            hex(&loaded.digest),
            loaded.decisions
        )),
        Err(error) => out.push(format!("{UNLOADED}: {error:?}")),
    }
    if prefix_digest(&bytes, reached.semantic) != Some(reached.prefix) {
        out.push("its bundle does not start with the prefix".into());
    }
    let at_delivery = reached.facts.at_delivery;
    out.extend(custody(
        &bytes,
        reached.semantic,
        reached.facts.upload,
        at_delivery,
    ));
    out
}

/// Explores `original` from milestone `name` within the manifest's tree
/// limits, the node at the plant's path planted, writing each leaf's bundle
/// into `dir`. The root collects its children within the manifest's
/// watchdog of its first fork, kills and reaps every child before a panic
/// in its own run propagates, and collects every child before it returns a
/// refusal.
///
/// # Errors
///
/// As [`explored`], for a refusal before the fork, a failed fork at the
/// root, or a milestone the run never reached.
pub(crate) fn explore(
    original: &[u8],
    name: &str,
    dir: &Path,
    plant: TreePlant,
) -> Result<Explored, Unbranched> {
    let (mut tree, ran) = explored(original, name, Mode::Fork(plant))?;
    if tree.report.is_some() {
        let bytes = ran.map(|(bytes, _)| bytes);
        finish_node(&mut tree, bytes, dir);
    }
    let children = std::mem::take(&mut tree.children);
    let ran = match ran {
        Ok(ran) => ran,
        Err(panic) => {
            let (_, processes): (Vec<_>, Vec<_>) = children.into_iter().unzip();
            #[expect(
                clippy::disallowed_methods,
                reason = "panic cleanup reaps the children against an immediate host deadline"
            )]
            fork::collect_all(processes, Instant::now());
            std::panic::resume_unwind(panic);
        }
    };
    let candidates = tree.candidates.unwrap_or(0);
    let forked = children.len() as u64;
    let lines = frontier_report(&[], (candidates, forked), children, tree.deadline(0));
    let reached = outcome(tree.reached, &tree.refused, ran.1 && !tree.diverged)?;
    Ok(Explored {
        reached,
        limits: tree.limits,
        parent: ran.1,
        census: Census::parse(&lines),
    })
}

#[cfg(test)]
pub(crate) mod tests;
