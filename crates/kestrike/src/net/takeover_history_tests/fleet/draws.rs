//! Each fleet decision identifies a candidate by index. [`Draws::record`] derives the decisions from a root and
//! [`Draws::replay`] reads them from a recorded tape. If `Chooser::index` fails, `Draws::value` returns a `Refusal`
//! before the caller applies the decision.
//!
//! Candidates for one decision share a domain and tag, so their big-endian values keep numeric order.

use crate::sim::choice::{CANDIDATE_LEN, Candidate, ChoiceError, Chooser, Domain, Site};

const SCHEDULE: u16 = 0;
const WORKLOAD: u16 = 1;

pub(crate) const OWNER: Site = Site {
    domain: Domain::Workload,
    actor: SCHEDULE,
    site: 1,
};
pub(crate) const STANDBY: Site = Site {
    domain: Domain::Workload,
    actor: SCHEDULE,
    site: 2,
};
pub(crate) const NEXT: Site = Site {
    domain: Domain::Workload,
    actor: SCHEDULE,
    site: 3,
};
pub(crate) const NEIGHBOUR: Site = Site {
    domain: Domain::Workload,
    actor: SCHEDULE,
    site: 4,
};
pub(crate) const ROUND: Site = Site {
    domain: Domain::Workload,
    actor: SCHEDULE,
    site: 5,
};
pub(crate) const OBJECT: Site = Site {
    domain: Domain::Workload,
    actor: WORKLOAD,
    site: 1,
};

pub(crate) const RECONCILER: Site = Site {
    domain: Domain::Workload,
    actor: SCHEDULE,
    site: 7,
};

/// The runnable actors of a host scenario's round once its hosts started: each running host, each tenure that steps and
/// each running reconciler, or one idle candidate when the round has none. The decision is forced to its first
/// candidate, so it changes no step; a replay whose round holds another set of runnable actors refuses it before any
/// actor of that round steps. The owner processes a host runs beside its serving tenures are not candidates: a
/// standby's or an unnamed host's wait, and every owner process the host loop runs between rounds (a queued takeover,
/// restart or rerun, a fresh activation).
pub(crate) const ACTORS: Site = Site {
    domain: Domain::Workload,
    actor: SCHEDULE,
    site: 8,
};

const SITES: [Site; 8] = [
    OWNER, STANDBY, NEXT, NEIGHBOUR, ROUND, OBJECT, RECONCILER, ACTORS,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Tag {
    Host = 1,
    Shard = 2,
    Round = 3,
    Object = 4,
    Actor = 5,
}

pub(crate) fn candidate(tag: Tag, value: u64) -> Candidate {
    let mut bytes = [0; CANDIDATE_LEN];
    bytes[0] = Domain::Workload as u8;
    bytes[1] = tag as u8;
    bytes[2..10].copy_from_slice(&value.to_be_bytes());
    Candidate(bytes)
}

/// `applied` counts the decisions completed before `value` or `finish` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) applied: u64,
    pub(crate) error: ChoiceError,
}

/// The decisions of one run, drawn from a root and recorded, or replayed from a recorded tape.
pub(crate) struct Draws {
    chooser: Chooser,
}

impl Draws {
    pub(crate) fn record(root: u64) -> Self {
        Self::launched(Chooser::record(root, &SITES))
    }

    pub(crate) fn replay(tape: Vec<u8>) -> Self {
        Self::launched(Chooser::replay(&SITES, tape))
    }

    fn launched(mut chooser: Chooser) -> Self {
        chooser.launch(SCHEDULE);
        chooser.launch(WORKLOAD);
        Self { chooser }
    }

    /// The index of the value the decision picks. Ascending `values` produce candidates in lexicographic order.
    ///
    /// # Errors
    ///
    /// If `Chooser::index` fails, `pick` returns a `Refusal` before the caller applies the decision.
    pub(crate) fn pick(&mut self, site: Site, tag: Tag, values: &[u64]) -> Result<usize, Refusal> {
        let candidates: Vec<Candidate> =
            values.iter().map(|&value| candidate(tag, value)).collect();
        let applied = self.chooser.decisions();
        (self.chooser.index(site, 0, &candidates)).map_err(|error| Refusal { applied, error })
    }

    /// The value [`Draws::pick`] picks.
    ///
    /// # Errors
    ///
    /// As `pick`.
    pub(crate) fn value(&mut self, site: Site, tag: Tag, values: &[u64]) -> Result<u64, Refusal> {
        Ok(values[self.pick(site, tag, values)?])
    }

    /// Records `index` as a forced decision among `values`.
    ///
    /// # Errors
    ///
    /// As `pick`, and a replay whose tape holds another index.
    pub(crate) fn forced(
        &mut self,
        site: Site,
        tag: Tag,
        values: &[u64],
        index: usize,
    ) -> Result<usize, Refusal> {
        self.chooser.force(index);
        let applied = self.chooser.decisions();
        let picked = self.pick(site, tag, values)?;
        if picked != index {
            let (index, len) = (picked as u64, values.len() as u64);
            let error = ChoiceError::Index { index, len };
            return Err(Refusal { applied, error });
        }
        Ok(picked)
    }

    pub(crate) fn decisions(&self) -> u64 {
        self.chooser.decisions()
    }

    /// The run's tape.
    ///
    /// # Errors
    ///
    /// If `Chooser::finish` fails, `finish` returns a `Refusal` with the chooser's error and final decision count.
    pub(crate) fn finish(self) -> Result<Vec<u8>, Refusal> {
        let applied = self.chooser.decisions();
        self.chooser
            .finish()
            .map_err(|error| Refusal { applied, error })
    }
}
