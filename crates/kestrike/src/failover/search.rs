//! A breadth-first search over the worlds of a [`Model`]: from one root, every enabled action of every reached state
//! in the model's fixed action order, with each reached world judged by the model's monitor hook and stored once by
//! its canonical form.
//!
//! - SHORTEST: states leave a FIFO queue in the order they were reached, so every state at depth `d` is expanded
//!   before any state at depth `d + 1`, and the first violation the search meets ends a shortest action path that
//!   breaks a monitor. The model's action order breaks ties between shortest paths.
//! - DETERMINISTIC: the FIFO queue and the model's action order fix the traversal, so a deterministic model yields
//!   the same totals, observations and paths for the same cap; canonical forms and observed names are kept in
//!   ordered sets.
//! - The search returns [`Verdict::Incomplete`] when the transition cap stops exploration, and
//!   [`Verdict::Unexpected`] when a step returns `Err`, before the monitor judges that step. A refusal the model
//!   carries in a successful step's event reaches the monitor.
//! - [`replay`] applies one supplied path and judges only the worlds on it. It applies an action only when the action
//!   is in the model's alphabet and enabled in the current world, the search's own action domain, and reports the
//!   first other action as [`End::Disabled`].

use std::collections::{BTreeSet, VecDeque};
use std::fmt::Debug;

pub(crate) trait Model {
    type World: Clone;
    type Action: Copy + Debug + PartialEq;
    /// What one step reports to the monitor hook beside the next world, such as the write the step committed.
    type Event;
    /// A world's canonical form: two worlds with one form have the same enabled actions and verdicts, and each action
    /// takes them to worlds with one form; the names a step records in [`Seen`] may differ between them.
    type Canon: Ord;

    fn root(&self) -> Self::World;

    /// Every action, in the fixed order the search tries them at each state.
    fn alphabet(&self) -> &[Self::Action];

    fn enabled(&self, world: &Self::World, action: Self::Action) -> bool;

    /// The kind of `action`; [`Seen::kinds`] records it when the search applies the action.
    fn kind(&self, action: Self::Action) -> &'static str;

    /// The successor of `world` under `action` and the step's event. The step records the decisions it calls and
    /// the witnesses it observes in `seen`.
    ///
    /// # Errors
    ///
    /// The model's description of a refusal that ends the search as a failure.
    fn step(
        &self,
        world: &Self::World,
        action: Self::Action,
        seen: &mut Seen,
    ) -> Result<(Self::World, Self::Event), String>;

    /// The first property `world` breaks, judged after the step that reported `event`, or at the root when `event`
    /// is `None`.
    fn monitor(&self, world: &Self::World, event: Option<&Self::Event>) -> Option<&'static str>;

    fn canonical(&self, world: &Self::World) -> Self::Canon;
}

/// The names a search observed: the production decisions its steps called, the witnesses they reported and the
/// action kinds it applied.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Seen {
    pub(crate) decisions: BTreeSet<&'static str>,
    pub(crate) witnesses: BTreeSet<&'static str>,
    pub(crate) kinds: BTreeSet<&'static str>,
}

impl Seen {
    pub(crate) fn decision(&mut self, name: &'static str) {
        self.decisions.insert(name);
    }

    pub(crate) fn witness(&mut self, name: &'static str) {
        self.witnesses.insert(name);
    }
}

/// How a search ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict<A> {
    /// Every state within the bound was reached and expanded, and every monitor held.
    Exhaustive,
    /// The transition cap stopped the search before it exhausted the bound.
    Incomplete,
    /// The world `path` reaches from the root breaks `property`; `path` is a shortest path that breaks a monitor.
    Violation {
        property: &'static str,
        path: Vec<A>,
    },
    /// The last action of `path` returned a refusal the model treats as a failure of the search.
    Unexpected { refusal: String, path: Vec<A> },
}

/// Totals of one search: distinct states stored, transitions applied and the depth of the deepest stored state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Totals {
    pub(crate) states: usize,
    pub(crate) transitions: u64,
    pub(crate) depth: u32,
}

#[derive(Debug)]
pub(crate) struct Report<A> {
    pub(crate) verdict: Verdict<A>,
    pub(crate) totals: Totals,
    pub(crate) seen: Seen,
}

/// Searches `model` from its root, applying at most `cap` transitions.
pub(crate) fn search<M: Model>(model: &M, cap: u64) -> Report<M::Action> {
    let root = model.root();
    let mut seen = Seen::default();
    let mut totals = Totals {
        states: 1,
        ..Totals::default()
    };
    let report = |verdict, totals, seen| Report {
        verdict,
        totals,
        seen,
    };
    if let Some(property) = model.monitor(&root, None) {
        let verdict = Verdict::Violation {
            property,
            path: Vec::new(),
        };
        return report(verdict, totals, seen);
    }
    let mut stored = BTreeSet::from([model.canonical(&root)]);
    // Each stored state's parent and the action that reached it, for the path of a failure.
    let mut nodes: Vec<Option<(usize, M::Action)>> = vec![None];
    let mut queue = VecDeque::from([(root, 0_usize, 0_u32)]);
    while let Some((world, node, depth)) = queue.pop_front() {
        for &action in model.alphabet() {
            if !model.enabled(&world, action) {
                continue;
            }
            if totals.transitions == cap {
                return report(Verdict::Incomplete, totals, seen);
            }
            totals.transitions += 1;
            seen.kinds.insert(model.kind(action));
            let (next, event) = match model.step(&world, action, &mut seen) {
                Ok(stepped) => stepped,
                Err(refusal) => {
                    let path = path_to(&nodes, node, action);
                    return report(Verdict::Unexpected { refusal, path }, totals, seen);
                }
            };
            if let Some(property) = model.monitor(&next, Some(&event)) {
                let path = path_to(&nodes, node, action);
                return report(Verdict::Violation { property, path }, totals, seen);
            }
            if stored.insert(model.canonical(&next)) {
                nodes.push(Some((node, action)));
                totals.states += 1;
                totals.depth = totals.depth.max(depth + 1);
                queue.push_back((next, nodes.len() - 1, depth + 1));
            }
        }
    }
    report(Verdict::Exhaustive, totals, seen)
}

/// The actions from the root to stored state `node`, then `last`.
fn path_to<A: Copy>(nodes: &[Option<(usize, A)>], mut node: usize, last: A) -> Vec<A> {
    let mut path = vec![last];
    while let Some((parent, action)) = nodes[node] {
        path.push(action);
        node = parent;
    }
    path.reverse();
    path
}

/// How a replay of a fixed path ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum End<A> {
    /// Every action of the path ran and every monitor held. A replay judges only the worlds on its path.
    Applied,
    /// The action at index `at` of the path lies outside the model's alphabet or is disabled in the world the actions
    /// before it reach; the replay applied only those earlier actions.
    Disabled { at: usize, action: A },
    /// The world the prefix `path` of the replayed path reaches breaks `property`: the empty prefix when the root
    /// breaks it, otherwise the prefix through the step that broke it.
    Violation {
        property: &'static str,
        path: Vec<A>,
    },
    /// The last action of `path` returned a refusal the model treats as a failure.
    Unexpected { refusal: String, path: Vec<A> },
}

/// One replay of a fixed path from the root: the event of each step it applied, how it ended, and the last world it
/// reached.
pub(crate) struct Replay<M: Model> {
    pub(crate) events: Vec<M::Event>,
    pub(crate) end: End<M::Action>,
    pub(crate) world: M::World,
}

/// Applies `path` from `model`'s root, judging every reached world, and stops at the first broken monitor, at the
/// first step that returns `Err`, or at the first action outside the model's alphabet or disabled in the current
/// world, as the search's own action domain does.
pub(crate) fn replay<M: Model>(model: &M, path: &[M::Action]) -> Replay<M> {
    let mut world = model.root();
    let mut seen = Seen::default();
    let mut events = Vec::new();
    let broken = |property: Option<&'static str>, at: usize| {
        property.map(|property| End::Violation {
            property,
            path: path[..at].to_vec(),
        })
    };
    if let Some(end) = broken(model.monitor(&world, None), 0) {
        return Replay { events, end, world };
    }
    for (at, &action) in path.iter().enumerate() {
        if !model.alphabet().contains(&action) || !model.enabled(&world, action) {
            let end = End::Disabled { at, action };
            return Replay { events, end, world };
        }
        let (next, event) = match model.step(&world, action, &mut seen) {
            Ok(stepped) => stepped,
            Err(refusal) => {
                let path = path[..=at].to_vec();
                let end = End::Unexpected { refusal, path };
                return Replay { events, end, world };
            }
        };
        let property = model.monitor(&next, Some(&event));
        events.push(event);
        world = next;
        if let Some(end) = broken(property, at + 1) {
            return Replay { events, end, world };
        }
    }
    Replay {
        events,
        end: End::Applied,
        world,
    }
}

impl<M: Model> Replay<M> {
    pub(crate) fn last(&self) -> &M::Event {
        self.events.last().expect("the replay applied a step")
    }
}

/// Searching `planted` under `cap` must report a violation of `property` along `path`. Replaying `path` on
/// `baseline` must apply every step with every monitor holding. `control` returns the baseline replay.
pub(crate) fn control<M: Model>(
    planted: &M,
    baseline: &M,
    cap: u64,
    property: &'static str,
    path: &[M::Action],
) -> Replay<M> {
    let path = path.to_vec();
    assert_eq!(
        search(planted, cap).verdict,
        Verdict::Violation {
            property,
            path: path.clone()
        }
    );
    let replayed = replay(baseline, &path);
    assert_eq!(replayed.end, End::Applied);
    replayed
}
