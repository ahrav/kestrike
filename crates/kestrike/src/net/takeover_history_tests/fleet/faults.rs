//! The fleet's fault script: actor-scoped store arms and outage windows, the hosts' reachability and delay matrix,
//! and episodes. An episode fires once, at the first step of the script at which its trigger holds, applies its
//! action to the hosts of its scope, and undoes the action at the first step `heal` rounds or more later when it
//! names a heal. The fleet steps the script once a host turn. A takeover's bring-up and a drain of the GETs in
//! flight run their rounds inside one turn, so an episode that falls due during them fires when that turn ends.
//!
//! The legal profile admits the faults a correct deployment meets: a host crash and its return, a pause, a link
//! drop, a delay, a partition, an isolation, a contract store arm, a store outage, a volume's stall, loss or
//! control-plane impairment, and the operator's release of a held replacement. A hostile kind breaks a premise
//! of the fleet's rules, and only the [`Hostile`] profile of that kind admits it. Before the run starts,
//! [`Faults::admit`] checks each episode against the run's profile.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use crate::storage::store::sim::{ActorFaults, Arm};

/// Rounds count from the first host round.
#[derive(Clone, Copy)]
pub(super) enum Trigger {
    AtTime(u64),
    /// The `occurrence`-th time, counted from 1, that the fleet log records `pattern`.
    After(Pattern, u32),
    /// The first round at whose start the predicate over the fleet's state holds.
    When(fn(&super::Fleet<'_>) -> bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pattern {
    /// A takeover returned its session, by itself or through the same-host restart its refusal licensed. A
    /// takeover whose compare-and-swap committed and whose device step then refused is not counted.
    TakeOver,
    /// A detector published a nomination.
    Nominated,
}

/// Member indices of hosts. A store arm at a host's index reaches that host's agent, recovery and standby wait
/// requests, and a store outage at a host's index stops those and the serving duties of each tenure the host holds
/// (`fleet::HostOut`);
/// the duties' own write arms go to a duty actor of their cell (`fleet::duty_actor`), which no scope names. A store
/// arm or outage at an index at or past the host count reaches reconciler `index - hosts`'s requests; a crash, a
/// pause and a link action name hosts alone.
pub(crate) type Scope = Vec<usize>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// A crash bypasses quiesce. Each scoped host drops its tenures, detector and pending device commands and keeps
    /// its local records and watermark log. The heal restarts the host under a new boot, and the host then restarts
    /// each shard it held when it stopped. A scoped host that is already down stays as it is.
    Crash,
    Pause,
    /// `Drop` cuts the links between each scoped host and each listed host.
    Drop(Vec<usize>),
    /// `Delay` delays the links between each scoped host and each listed host by `rounds` rounds.
    Delay(Vec<usize>, u64),
    /// `Partition` cuts the links between the scope and every host outside it; a scope of one host is an isolation.
    Partition,
    Store(Arm),
    Outage,
    /// An unknown registrant joins the reservation table of the shard at this cell index.
    Register(usize),
    /// Every command on the volume of the shard at this cell index stalls with no error; the heal clears the stall.
    Stall(usize),
    /// The volume of the shard at this cell index loses its data, and the zone double lists it in state `error`.
    LoseVolume(usize),
    /// The zone double lists the volume of the shard at this cell index with status `impaired`; the heal lists it
    /// `ok` again.
    Impair(usize),
    /// The operator releases the held replacement receipt of the shard at this cell index.
    Release(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Crash,
    Pause,
    LinkDrop,
    Delay,
    Partition,
    Isolation,
    StoreArm,
    StoreOutage,
    /// A stall, a loss or a control-plane impairment of one volume.
    Volume,
    OperatorRelease,
    /// `Hostile(StoreKill)` covers the kill arms of the store double: a lost write, a double win or a stale
    /// current read.
    Hostile(Hostile),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hostile {
    StoreKill,
    Clock,
    NoExclusion,
    ForeignRegistrant,
    Provider,
}

impl Hostile {
    pub(crate) const ALL: [Self; 5] = [
        Self::StoreKill,
        Self::Clock,
        Self::NoExclusion,
        Self::ForeignRegistrant,
        Self::Provider,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::StoreKill => "hostile:store-kill",
            Self::Clock => "hostile:clock",
            Self::NoExclusion => "hostile:no-exclusion",
            Self::ForeignRegistrant => "hostile:foreign-registrant",
            Self::Provider => "hostile:provider",
        }
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::StoreKill => 1,
            Self::Clock => 2,
            Self::NoExclusion => 3,
            Self::ForeignRegistrant => 4,
            Self::Provider => 5,
        }
    }
}

impl Kind {
    pub(super) fn of(episode: &Episode) -> Self {
        match &episode.action {
            Action::Crash => Self::Crash,
            Action::Pause => Self::Pause,
            Action::Drop(_) => Self::LinkDrop,
            Action::Delay(..) => Self::Delay,
            Action::Partition if episode.scope.len() == 1 => Self::Isolation,
            Action::Partition => Self::Partition,
            Action::Store(Arm::LostWrite | Arm::DoubleWin | Arm::StaleCurrentRead) => {
                Self::Hostile(Hostile::StoreKill)
            }
            Action::Store(_) => Self::StoreArm,
            Action::Outage => Self::StoreOutage,
            Action::Register(_) => Self::Hostile(Hostile::ForeignRegistrant),
            Action::Stall(_) | Action::LoseVolume(_) | Action::Impair(_) => Self::Volume,
            Action::Release(_) => Self::OperatorRelease,
        }
    }

    /// Every profile admits a legal kind, and only the hostile profile of a hostile kind admits that kind.
    pub(crate) fn admitted(self, profile: super::Profile) -> bool {
        let hostile = match self {
            Self::Hostile(hostile) => Some(hostile),
            _ => None,
        };
        match (hostile, profile) {
            (None, _) => true,
            (Some(kind), super::Profile::Arm(of)) => kind == of,
            (Some(_), _) => false,
        }
    }
}

#[derive(Clone)]
pub(super) struct Episode {
    pub(super) trigger: Trigger,
    pub(super) scope: Scope,
    pub(super) action: Action,
    pub(super) heal: Option<u64>,
}

/// The profile refuses the script's episode at `episode`, or, at the script's length, the scenario's own duty-store
/// fault, which no episode carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Inadmissible {
    pub(crate) episode: usize,
    pub(crate) kind: Kind,
}

/// The reachability and delay of each ordered pair of hosts. A pair outside both maps delivers in the round it is
/// sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HostLinks {
    cut: BTreeMap<(usize, usize), u32>,
    /// The delays in force on each pair, one for each episode that delays it.
    delay: BTreeMap<(usize, usize), Vec<u64>>,
}

impl HostLinks {
    pub(crate) fn reaches(&self, from: usize, to: usize) -> bool {
        from == to || !self.cut.contains_key(&(from, to))
    }

    /// The largest delay in force on the pair.
    pub(crate) fn delay(&self, from: usize, to: usize) -> u64 {
        let held = self.delay.get(&(from, to));
        held.and_then(|held| held.iter().copied().max())
            .unwrap_or(0)
    }

    /// A link resumes carrying traffic when all cuts affecting that pair have healed.
    fn cut(&mut self, pairs: &[(usize, usize)], on: bool) {
        for &(a, b) in pairs {
            for pair in [(a, b), (b, a)] {
                let count = self.cut.entry(pair).or_default();
                *count = if on {
                    *count + 1
                } else {
                    count.saturating_sub(1)
                };
                if *count == 0 {
                    self.cut.remove(&pair);
                }
            }
        }
    }

    /// Puts a delay of `rounds` in force on each pair when `on`, and otherwise takes one such delay off, so the
    /// delays of other episodes on the pair stay in force.
    fn delay_by(&mut self, pairs: &[(usize, usize)], rounds: u64, on: bool) {
        for &(a, b) in pairs {
            for pair in [(a, b), (b, a)] {
                let held = self.delay.entry(pair).or_default();
                if on {
                    held.push(rounds);
                } else if let Some(at) = held.iter().position(|&of| of == rounds) {
                    held.swap_remove(at);
                }
                if held.is_empty() {
                    self.delay.remove(&pair);
                }
            }
        }
    }
}

/// The state the crashes and pauses in force hold a host in. A crash outranks a pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Hold {
    Free,
    Paused,
    Down,
}

impl Hold {
    /// The effects that take `member` from `before` to `after`. A host that leaves a crash for a pause returns
    /// under a new boot and pauses.
    fn moves(before: Self, after: Self, member: usize) -> Vec<Effect> {
        match (before, after) {
            (Self::Free, Self::Paused) => vec![Effect::Pause(member)],
            (Self::Free | Self::Paused, Self::Down) => vec![Effect::Crash(member)],
            (Self::Down, Self::Free) => vec![Effect::Return(member)],
            (Self::Down, Self::Paused) => vec![Effect::Return(member), Effect::Pause(member)],
            (Self::Paused, Self::Free) => vec![Effect::Resume(member)],
            _ => Vec::new(),
        }
    }
}

/// The fleet makes these host changes; [`Faults`] applies the link and store changes itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    Crash(usize),
    Return(usize),
    Pause(usize),
    Resume(usize),
    /// A link cut fired; `until` is the round its heal falls due, and `isolated` the scope a partition cuts off.
    Cut {
        until: Option<u64>,
        isolated: Vec<usize>,
    },
    Register(usize),
    Stall(usize),
    Unstall(usize),
    LoseVolume(usize),
    /// The zone double lists the cell's volume impaired when `true` and `ok` when `false`.
    Impair(usize, bool),
    Release(usize),
}

/// [`Faulted`] stores read `store`.
///
/// [`Faulted`]: crate::storage::store::sim::Faulted
pub(super) struct Faults {
    pub(super) episodes: Vec<Episode>,
    /// The round each episode fired at, and whether its heal ran.
    pub(crate) fired: Vec<Option<(u64, bool)>>,
    pub(crate) store: Rc<RefCell<ActorFaults>>,
    /// The tickets of each store episode's arms, in scope order, from its firing to its heal.
    armed: Vec<Vec<u64>>,
    pub(crate) links: HostLinks,
    members: usize,
}

impl Faults {
    pub(super) fn new(episodes: Vec<Episode>, members: usize) -> Self {
        Self {
            fired: vec![None; episodes.len()],
            armed: vec![Vec::new(); episodes.len()],
            episodes,
            store: Rc::default(),
            links: HostLinks::default(),
            members,
        }
    }

    /// # Errors
    ///
    /// The first episode in script order whose kind the profile refuses.
    pub(crate) fn admit(&self, profile: super::Profile) -> Result<(), Inadmissible> {
        for (episode, of) in self.episodes.iter().enumerate() {
            let kind = Kind::of(of);
            if !kind.admitted(profile) {
                return Err(Inadmissible { episode, kind });
            }
        }
        Ok(())
    }

    /// A fired episode with a heal settles once the heal ran.
    pub(crate) fn settled(&self) -> bool {
        (self.episodes.iter().zip(&self.fired)).all(|(episode, fired)| {
            fired.is_some_and(|(_, healed)| healed || episode.heal.is_none())
        })
    }

    pub(crate) fn last_change(&self) -> Option<u64> {
        (self.episodes.iter().zip(&self.fired))
            .filter_map(|(episode, fired)| {
                let (at, healed) = (*fired)?;
                Some(match (healed, episode.heal) {
                    (true, Some(heal)) => at + heal,
                    _ => at,
                })
            })
            .max()
    }

    fn pairs(&self, episode: &Episode) -> Vec<(usize, usize)> {
        let scope: BTreeSet<usize> = episode.scope.iter().copied().collect();
        let others: Vec<usize> = match &episode.action {
            Action::Drop(to) | Action::Delay(to, _) => to.clone(),
            _ => (0..self.members).filter(|at| !scope.contains(at)).collect(),
        };
        (scope.iter())
            .flat_map(|&a| others.iter().map(move |&b| (a, b)))
            .collect()
    }

    /// Fires every episode whose trigger holds and heals every episode whose heal falls due at `round`, in script
    /// order, and returns the host effects in that order.
    pub(crate) fn step(&mut self, round: u64, holds: impl Fn(&Trigger) -> bool) -> Vec<Effect> {
        let mut effects = Vec::new();
        for at in 0..self.episodes.len() {
            let episode = self.episodes[at].clone();
            if self.fired[at].is_none() && holds(&episode.trigger) {
                self.fired[at] = Some((round, false));
                effects.extend(self.apply(at, true, round));
            }
            if let Some((from, false)) = self.fired[at]
                && episode.heal.is_some_and(|heal| from + heal <= round)
            {
                self.fired[at] = Some((from, true));
                effects.extend(self.apply(at, false, round));
            }
        }
        effects
    }

    /// The actions of the episodes other than `at` that fired, have not healed and name `member`.
    fn others(&self, at: usize, member: usize) -> impl Iterator<Item = &Action> {
        let fired = self.episodes.iter().zip(&self.fired).enumerate();
        fired.filter_map(move |(other, (episode, fired))| {
            let holds =
                other != at && matches!(fired, Some((_, false))) && episode.scope.contains(&member);
            holds.then_some(&episode.action)
        })
    }

    /// The state the episodes other than `at` hold `member` in.
    fn hold(&self, at: usize, member: usize) -> Hold {
        let holds = self.others(at, member).map(|action| match action {
            Action::Crash => Hold::Down,
            Action::Pause => Hold::Paused,
            _ => Hold::Free,
        });
        holds.max().unwrap_or(Hold::Free)
    }

    /// Applies episode `at`'s action when `on` and undoes it otherwise. A crash or a pause moves a host between
    /// the states its episodes in force hold it in: down under a crash, paused under a pause and no crash. The
    /// heal of a partition reconnects a host that no crash, pause or other partition holds.
    fn apply(&mut self, at: usize, on: bool, round: u64) -> Vec<Effect> {
        let episode = &self.episodes[at].clone();
        let scope = episode.scope.iter().copied();
        match &episode.action {
            Action::Crash | Action::Pause => {
                let own = match episode.action {
                    Action::Crash => Hold::Down,
                    _ => Hold::Paused,
                };
                let moves = scope.flat_map(|member| {
                    let rest = self.hold(at, member);
                    let (before, after) = match on {
                        true => (rest, rest.max(own)),
                        false => (rest.max(own), rest),
                    };
                    Hold::moves(before, after, member)
                });
                moves.collect()
            }
            Action::Drop(_) | Action::Partition => {
                let pairs = self.pairs(episode);
                self.links.cut(&pairs, on);
                let until = episode.heal.map(|heal| round + heal);
                let isolated = match episode.action {
                    Action::Partition => episode.scope.clone(),
                    _ => Vec::new(),
                };
                let free = |&member: &usize| {
                    let cut = self
                        .others(at, member)
                        .any(|action| *action == Action::Partition);
                    self.hold(at, member) == Hold::Free && !cut
                };
                match on {
                    true => vec![Effect::Cut { until, isolated }],
                    false => (isolated.into_iter().filter(free))
                        .map(Effect::Resume)
                        .collect(),
                }
            }
            Action::Delay(_, rounds) => {
                let pairs = self.pairs(episode);
                self.links.delay_by(&pairs, *rounds, on);
                Vec::new()
            }
            Action::Store(arm) => {
                let mut store = self.store.borrow_mut();
                if on {
                    let tickets = scope.map(|actor| store.arm(actor as u32, *arm));
                    self.armed[at] = tickets.collect();
                } else {
                    for (actor, ticket) in scope.zip(std::mem::take(&mut self.armed[at])) {
                        store.withdraw(actor as u32, ticket);
                    }
                }
                Vec::new()
            }
            Action::Outage => {
                let until = episode.heal.map_or(u64::MAX, |heal| round + heal);
                for actor in scope.filter(|_| on) {
                    (self.store.borrow_mut()).outage(Some(actor as u32), round, until);
                }
                Vec::new()
            }
            Action::Register(at) if on => vec![Effect::Register(*at)],
            Action::Stall(at) if on => vec![Effect::Stall(*at)],
            Action::Stall(at) => vec![Effect::Unstall(*at)],
            Action::LoseVolume(at) if on => vec![Effect::LoseVolume(*at)],
            Action::Impair(at) => vec![Effect::Impair(*at, on)],
            Action::Release(at) if on => vec![Effect::Release(*at)],
            Action::Register(_) | Action::LoseVolume(_) | Action::Release(_) => Vec::new(),
        }
    }
}
