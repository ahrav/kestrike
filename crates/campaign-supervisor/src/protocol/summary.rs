//! A bundle summary, as the run and inspect forms print it, and the run
//! form's panic line.
//!
//! Every summary key appears at most once. The always-printed keys are
//! required; the rest follow the bundle: `cause` exactly when the bundle
//! does not count, `unsuccessful` only then; `identity` only beside a
//! complete violation; `ledger` exactly for a profile the listing classes
//! as recovery, or at most once when the summary names no profile
//! (`profile: unavailable`). A `credited` or `inconclusive` ledger requires
//! a recovery census. An `unrecorded` or `mismatched` ledger carries the
//! census when its events rebuild; a `refused` ledger ends at the verdict.
//! The census contains `stages` and `limits`.
//! Capability version 5 requires one `windows` entry per row: `name=count` or `name=unplanned`.
//!
//! A recovery stage census requires `planned >= reached >= activated >=
//! recovered >= checked` and `activated + skipped <= planned`.
//!
//! Cluster summaries print `topology`, `coverage` and `unavailable`
//! exactly for a profile the listing declares a cluster line for,
//! `topology` and `coverage` both `unavailable` or neither, and the
//! topology's owners equal to the `owners` line, that line inside the
//! declaration's owner range, the drawn keys at least the owners and inside
//! the declaration's key range raised to the owners, and the `clients` line
//! equal to the declaration's; a named profile without a cluster line
//! prints the owners and clients its history line declares, or else the
//! listing's fixed ones. `skipped_us` is at most `virtual_us`.
//!
//! A field the bundle records no value for reads as `None`, never as zero,
//! and the fields one source records are available together: the work
//! counts unless the terminal is truncated, the three declared limits, and
//! the counts a composed world's stop event records, whose operations and
//! witnesses a scripted history leaves unavailable. `incarnations` and
//! `retained_depth` print `unavailable` in this version. A named profile is
//! one the listing admits.

use crate::record::{Digest, Text};

use super::Error;
use super::listing::{CRASH_WINDOWS, Class, Listing};
use super::pairs::{Pairs, available, count, counts, digest, flag, hex, measure, owned};
use super::terminal::{Infrastructure, Outcome, STOPS, Terminal};

/// The summary format version this parser reads.
pub const SUMMARY: u32 = 1;

/// Hexadecimal digits of a failure identity, a 44-byte event payload.
const IDENTITY: usize = 88;

/// The most bytes of an unsuccessful rule: an event payload less its three
/// code bytes.
const RULE: usize = 41;

/// The coverage counters a cluster summary prints, in its order.
pub const COVERAGE: [&str; 10] = [
    "published",
    "hits",
    "misses",
    "refused",
    "invalidated",
    "cancelled",
    "cross",
    "reused",
    "healthy",
    "faults",
];

/// A bundle summary; [`Summary::parse`] holds its grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub digest: Digest,
    pub decisions: Option<u64>,
    pub terminal: Terminal,
    pub counts: bool,
    pub turns: Option<u64>,
    pub progress: Option<u64>,
    pub virtual_us: Option<u64>,
    pub skipped_us: Option<u64>,
    /// The recorded profile, when the worker's catalog lists its name.
    pub profile: Option<String>,
    pub declared_turns: Option<u64>,
    pub declared_same_time: Option<u64>,
    pub declared_no_progress: Option<u64>,
    /// How the run stopped: one of the worker's stop names, or `unknown`
    /// for a code the worker does not name; `None` for a bundle without a
    /// stop event.
    pub stop: Option<String>,
    pub boundaries_checked: Option<u64>,
    pub operations: Option<u64>,
    pub witnesses: Option<u64>,
    pub faults_delivered: Option<u64>,
    pub owners: Option<u64>,
    pub clients: Option<u64>,
    pub cluster: Option<Cluster>,
    pub cause: Option<String>,
    /// The rule of the first unsuccessful check, as recorded: at most 41
    /// bytes.
    pub unsuccessful: Option<Text>,
    pub identity: Option<FailureIdentity>,
    pub ledger: Option<Ledger>,
    pub recovery: Option<Recovery>,
}

/// A complete violation's failure identity: its 44-byte event payload as
/// the 88 lowercase hexadecimal digits the worker printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureIdentity(pub(super) String);

impl FailureIdentity {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A cluster profile's summary lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    /// The topology and coverage, or `None` when the bundle lacks its stop
    /// or coverage event.
    pub drawn: Option<Drawn>,
    /// The dimensions the profile leaves unexercised, as its listing
    /// declaration names them.
    pub unavailable: String,
}

/// A cluster run's drawn topology and the coverage it reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drawn {
    pub topology: Topology,
    /// The count of each of the [`COVERAGE`] counters, in that order, each
    /// a four-byte field of the coverage event.
    pub coverage: [u32; COVERAGE.len()],
}

/// A cluster run's drawn topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topology {
    pub owners: u64,
    pub keys: u64,
    /// The hot key's index below `keys`.
    pub hot: u64,
}

/// A recovery bundle's campaign verdict, with the worker's text of a gap,
/// error or mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ledger {
    /// The campaign ledger credits the run.
    Credited,
    /// The ledger leaves a gap, so the run earns no credit.
    Inconclusive(String),
    /// The ledger failed to rebuild.
    Refused(String),
    /// The worker reports `unrecorded` for a recovery bundle without an admitted
    /// recovery record. Its events can still rebuild into a census.
    Unrecorded,
    /// The bundle's recovery record differs from the inspecting worker's.
    Mismatched(String),
}

impl Ledger {
    /// The verdict word the worker prints first on the ledger line.
    pub fn verdict(&self) -> &'static str {
        match self {
            Self::Credited => "credited",
            Self::Inconclusive(_) => "inconclusive",
            Self::Refused(_) => "refused",
            Self::Unrecorded => "unrecorded",
            Self::Mismatched(_) => "mismatched",
        }
    }
}

/// The census a worker prints when it rebuilds a recovery ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    pub stages: Stages,
    pub limits: String,
    /// Window rows in wire order. Each numeric value counts cuts reported for one
    /// planned row, and the values sum to at most `stages.checked`.
    /// `Some(0)` marks a planned gap; `None` marks an unplanned row.
    /// The inspecting executable uses the recorded manifest's profile name to select its own cut table.
    /// At capability versions 1 through 4 a valid census omits the line and yields an empty list.
    pub windows: Vec<(String, Option<u64>)>,
}

/// How many recovery cuts reached each stage, from planned to skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stages {
    pub planned: u64,
    pub reached: u64,
    pub activated: u64,
    pub recovered: u64,
    pub checked: u64,
    pub skipped: u64,
}

/// The run form's output: a summary, or the one line a run that panicked
/// prints, holding the panic's location and payload. A panicked run is
/// incomplete evidence and supplies no summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Run {
    Summary(Box<Summary>),
    Panicked(String),
}

impl Run {
    /// The run form's output `text`: output whose first line is a `run:`
    /// line is the panic form, with that line alone; any other output is a
    /// summary.
    ///
    /// # Errors
    ///
    /// The errors of [`Summary::parse`] for a summary. For the panic form,
    /// [`Error::Torn`] for output cut short, [`Error::Repeated`] for a
    /// second `run:` line, [`Error::Unknown`] for a line of another key and
    /// [`Error::Unpaired`] for a line with no `": "`, and [`Error::Value`]
    /// for a `run:` line that names no panic.
    pub fn parse(text: &str, listing: &Listing) -> Result<Self, Error> {
        if !text.starts_with("run: ") {
            return Summary::parse(text, listing).map(|summary| Self::Summary(Box::new(summary)));
        }
        let mut lines = Pairs::lines(text)?;
        let run = lines.one("run")?;
        lines.finish()?;
        run.strip_prefix("the run panicked at ")
            .filter(|panic| !panic.is_empty())
            .map(|panic| Self::Panicked(panic.to_owned()))
            .ok_or(Error::Value("run"))
    }
}

impl Summary {
    /// The summary `text` prints, judged against the archive's `listing`.
    ///
    /// # Errors
    ///
    /// A missing final newline gives [`Error::Torn`]. A line missing its key-value
    /// separator gives [`Error::Unpaired`]. A missing required line gives [`Error::Missing`].
    /// A second occurrence of a key the form expects at most once gives [`Error::Repeated`].
    /// The parser returns [`Error::Unknown`] for any key left over after it parses the form.
    /// Invalid field values give [`Error::Value`]; contradictory fields give [`Error::Inconsistent`].
    pub fn parse(text: &str, listing: &Listing) -> Result<Self, Error> {
        let mut lines = Pairs::lines(text)?;
        if lines.take("summary", count)? != u64::from(SUMMARY) {
            return Err(Error::Value("summary"));
        }
        let mut summary = Self {
            digest: lines.take("digest", digest)?,
            decisions: lines.take("decisions", measure)?,
            terminal: lines.take("terminal", Terminal::parse)?,
            counts: lines.take("counts", flag)?,
            turns: lines.take("turns", measure)?,
            progress: lines.take("progress", measure)?,
            virtual_us: lines.take("virtual_us", measure)?,
            skipped_us: lines.take("skipped_us", measure)?,
            profile: available(lines.one("profile")?)
                .map(|name| owned(name, "profile"))
                .transpose()?,
            declared_turns: lines.take("declared_turns", measure)?,
            declared_same_time: lines.take("declared_same_time", measure)?,
            declared_no_progress: lines.take("declared_no_progress", measure)?,
            stop: available(lines.one("stop")?)
                .map(|stop| stopped(stop, &["unknown"]))
                .transpose()?,
            boundaries_checked: lines.take("boundaries_checked", measure)?,
            operations: lines.take("operations", measure)?,
            witnesses: lines.take("witnesses", measure)?,
            faults_delivered: lines.take("faults_delivered", measure)?,
            owners: lines.take("owners", measure)?,
            clients: lines.take("clients", measure)?,
            cluster: None,
            cause: lines
                .optional("cause")?
                .map(|cause| owned(cause, "cause"))
                .transpose()?,
            unsuccessful: lines.optional("unsuccessful")?.map(rule).transpose()?,
            identity: lines
                .optional("identity")?
                .map(|id| hex(id, IDENTITY, "identity").map(FailureIdentity))
                .transpose()?,
            ledger: None,
            recovery: None,
        };
        for key in ["incarnations", "retained_depth"] {
            if available(lines.one(key)?).is_some() {
                return Err(Error::Value(key));
            }
        }
        if let Some(name) = &summary.profile {
            if !listing.admits(name) {
                return Err(Error::Value("profile"));
            }
            if let Some(declared) = listing.cluster(name) {
                let printed = cluster(&mut lines)?;
                if declared.field("unavailable") != Some(printed.unavailable.as_str()) {
                    return Err(Error::Inconsistent(
                        "the unavailable dimensions differ from the cluster declaration",
                    ));
                }
                if summary.clients.is_some() && summary.clients != Some(declared.clients()?) {
                    return Err(Error::Inconsistent(
                        "the clients disagree with the cluster declaration",
                    ));
                }
                let (low, high) = declared.owners()?;
                if summary
                    .owners
                    .is_some_and(|owners| !(low..=high).contains(&owners))
                {
                    return Err(Error::Inconsistent(
                        "the owners lie outside the cluster declaration's range",
                    ));
                }
                // A run draws its key count inside the declared range, then
                // raises it to its owner count.
                let (low, high) = declared.keys()?;
                if printed.drawn.as_ref().is_some_and(|drawn| {
                    let Topology { owners, keys, .. } = drawn.topology;
                    keys < owners || keys < low || keys > high.max(owners)
                }) {
                    return Err(Error::Inconsistent(
                        "the drawn keys lie outside the cluster declaration's range",
                    ));
                }
                summary.cluster = Some(printed);
            }
        }
        // The worker judges a ledger by the recorded profile, which a
        // summary whose manifest does not parse names as unavailable; an
        // admitted name that is no recovery profile prints no ledger.
        let listed = summary
            .profile
            .as_deref()
            .and_then(|name| listing.profile(name));
        let class = listed.map(|profile| profile.class);
        let ledger = match (&summary.profile, class) {
            (_, Some(Class::Recovery)) => Some(lines.take("ledger", ledger)?),
            (None, _) => lines
                .optional("ledger")?
                .map(|text| ledger(text, "ledger"))
                .transpose()?,
            _ => None,
        };
        if let Some(verdict) = &ledger {
            summary.recovery = recovery(&mut lines, verdict, listing.capabilities)?;
        } else if summary.profile.is_none() {
            // A census prints only beside its ledger.
            let stages = lines.optional("stages")?;
            if stages.or(lines.optional("limits")?).is_some() {
                return Err(Error::Missing("ledger"));
            }
        }
        summary.ledger = ledger;
        lines.finish()?;
        summary.check(class == Some(Class::History))?;
        // Every profile without a cluster declaration runs the fixed
        // topology, or the topology its history line declares; a recovery
        // bundle records no stop composition.
        let expected = listed
            .and_then(|profile| profile.topology)
            .unwrap_or(listing.topology);
        if summary.cluster.is_none()
            && summary.profile.is_some()
            && summary.owners.is_some()
            && (summary.owners, summary.clients) != (Some(expected.owners), Some(expected.clients))
        {
            return Err(Error::Inconsistent(
                "the owners and clients disagree with the profile's topology",
            ));
        }
        Ok(summary)
    }

    /// Refuses lines that disagree: a bundle counts exactly when its
    /// terminal passes and any ledger credits it, names a cause exactly
    /// when it does not count, an unsuccessful rule only then and an
    /// identity only beside a complete violation; each source's fields
    /// are available together, as the module states, where `scripted`
    /// names a history profile; `skipped_us` is at most `virtual_us`; and
    /// a drawn topology's owners equal the `owners` line.
    fn check(&self, scripted: bool) -> Result<(), Error> {
        let truncated = self.terminal == Terminal::Infrastructure(Infrastructure::Truncated);
        let work = [
            self.decisions,
            self.turns,
            self.progress,
            self.virtual_us,
            self.skipped_us,
        ];
        if work.iter().any(|value| value.is_some() == truncated) {
            return Err(Error::Inconsistent(
                "the work counts are available exactly when the terminal is not truncated",
            ));
        }
        if self.skipped_us > self.virtual_us {
            return Err(Error::Inconsistent("the skipped time exceeds the clock"));
        }
        let declared = [
            self.declared_turns,
            self.declared_same_time,
            self.declared_no_progress,
        ];
        // The profile and the limits come from one recorded manifest.
        if declared
            .iter()
            .any(|value| value.is_some() != declared[0].is_some())
            || (self.profile.is_some() && declared[0].is_none())
        {
            return Err(Error::Inconsistent(
                "the declared limits are available together, and beside a profile",
            ));
        }
        let composed = self.boundaries_checked.is_some();
        let acted = composed && !scripted;
        if [self.faults_delivered, self.owners, self.clients]
            .iter()
            .any(|value| value.is_some() != composed)
            || [self.operations, self.witnesses]
                .iter()
                .any(|value| value.is_some() != acted)
            || (composed && self.stop.is_none())
            || (!composed
                && self
                    .cluster
                    .as_ref()
                    .is_some_and(|lines| lines.drawn.is_some()))
        {
            return Err(Error::Inconsistent(
                "the observed counts are available together with their stop event",
            ));
        }
        let drawn = self.cluster.as_ref().and_then(|lines| lines.drawn.as_ref());
        if drawn.is_some_and(|drawn| Some(drawn.topology.owners) != self.owners) {
            return Err(Error::Inconsistent(
                "the topology's owners disagree with the owners line",
            ));
        }
        let credited = self
            .ledger
            .as_ref()
            .is_none_or(|ledger| *ledger == Ledger::Credited);
        let violation = matches!(
            self.terminal,
            Terminal::Complete {
                outcome: Outcome::Violation,
                ..
            }
        );
        if self.counts != (self.terminal.passes() && credited) {
            return Err(Error::Inconsistent(
                "counts disagrees with the terminal and the ledger",
            ));
        }
        if self.counts && self.cause.is_some() {
            return Err(Error::Inconsistent("a counting bundle names a cause"));
        }
        if !self.counts && self.cause.is_none() {
            return Err(Error::Missing("cause"));
        }
        if self.counts && self.unsuccessful.is_some() {
            return Err(Error::Inconsistent(
                "a counting bundle names an unsuccessful rule",
            ));
        }
        if self.identity.is_some() && !violation {
            return Err(Error::Inconsistent(
                "an identity beside no complete violation",
            ));
        }
        Ok(())
    }
}

// The worker checks the recovery record before rebuilding the ledger for its verdict.
// An unrecorded or mismatched verdict can therefore accompany a census from the events.
fn recovery(
    lines: &mut Pairs<'_>,
    verdict: &Ledger,
    capabilities: u32,
) -> Result<Option<Recovery>, Error> {
    let census = match verdict {
        Ledger::Credited | Ledger::Inconclusive(_) => lines.one("stages")?,
        Ledger::Unrecorded | Ledger::Mismatched(_) => match lines.optional("stages")? {
            Some(census) => census,
            // Limits print only after their stages.
            None if lines.optional("limits")?.is_some() => return Err(Error::Missing("stages")),
            None => return Ok(None),
        },
        Ledger::Refused(_) => return Ok(None),
    };
    let [planned, reached, activated, recovered, checked, skipped] = counts(
        census,
        "planned={} reached={} activated={} recovered={} checked={} skipped={}",
        "stages",
    )?;
    // A cut passes planned, reached, activated, recovered and checked in
    // order, or leaves for skipped from planned or reached.
    if [reached, activated, recovered, checked]
        .windows(2)
        .any(|pair| pair[1] > pair[0])
        || reached > planned
    {
        return Err(Error::Inconsistent(
            "a stage counts more cuts than the stage before it",
        ));
    }
    if activated
        .checked_add(skipped)
        .is_none_or(|apart| apart > planned)
    {
        return Err(Error::Inconsistent(
            "the activated and skipped cuts exceed the planned",
        ));
    }
    let limits = lines.take("limits", owned)?;
    let windows = if capabilities >= CRASH_WINDOWS {
        lines.take("windows", windows)?
    } else {
        Vec::new()
    };
    // A counted cut passed its check and belongs to one row.
    if windows
        .iter()
        .filter_map(|(_, count)| *count)
        .try_fold(0, u64::checked_add)
        .is_none_or(|counted| counted > checked)
    {
        return Err(Error::Inconsistent(
            "the window counts exceed the checked cuts",
        ));
    }
    Ok(Some(Recovery {
        stages: Stages {
            planned,
            reached,
            activated,
            recovered,
            checked,
            skipped,
        },
        limits,
        windows,
    }))
}

fn windows(text: &str, key: &'static str) -> Result<Vec<(String, Option<u64>)>, Error> {
    let mut seen = std::collections::HashSet::new();
    text.split(' ')
        .map(|entry| {
            let (name, value) = entry.split_once('=').ok_or(Error::Value(key))?;
            if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(Error::Value(key));
            }
            if !seen.insert(name) {
                return Err(Error::Repeated(format!("window {name}")));
            }
            let value = if value == "unplanned" {
                None
            } else {
                Some(count(value, key)?)
            };
            Ok((name.to_owned(), value))
        })
        .collect()
}

/// An unsuccessful rule: record text of at most [`RULE`] bytes.
fn rule(text: &str) -> Result<Text, Error> {
    Text::new(text)
        .filter(|_| text.len() <= RULE)
        .ok_or(Error::Value("unsuccessful"))
}

/// A stop name: one of [`STOPS`] or of `more`.
pub(super) fn stopped(text: &str, more: &[&str]) -> Result<String, Error> {
    STOPS
        .iter()
        .chain(more)
        .any(|name| *name == text)
        .then(|| text.to_owned())
        .ok_or(Error::Value("stop"))
}

fn cluster(lines: &mut Pairs<'_>) -> Result<Cluster, Error> {
    let topology = available(lines.one("topology")?);
    let coverage = available(lines.one("coverage")?);
    let drawn = match (topology, coverage) {
        (Some(topology), Some(coverage)) => {
            let [owners, keys, hot] = counts(topology, "owners={} keys={} hot={}", "topology")?;
            if hot >= keys {
                return Err(Error::Value("topology"));
            }
            Some(Drawn {
                topology: Topology { owners, keys, hot },
                coverage: reached(coverage)?,
            })
        }
        (None, None) => None,
        _ => {
            return Err(Error::Inconsistent(
                "topology and coverage print from one coverage event",
            ));
        }
    };
    Ok(Cluster {
        drawn,
        unavailable: lines.take("unavailable", owned)?,
    })
}

/// A `coverage` line: each of the [`COVERAGE`] counters as `name=count`,
/// in that order.
fn reached(text: &str) -> Result<[u32; COVERAGE.len()], Error> {
    let pattern = COVERAGE.map(|name| format!("{name}={{}}")).join(" ");
    let wide: [u64; COVERAGE.len()] = counts(text, &pattern, "coverage")?;
    let mut narrow = [0u32; COVERAGE.len()];
    for (narrow, wide) in narrow.iter_mut().zip(wide) {
        *narrow = u32::try_from(wide).map_err(|_| Error::Value("coverage"))?;
    }
    Ok(narrow)
}

fn ledger(text: &str, key: &'static str) -> Result<Ledger, Error> {
    let (verdict, detail) = text
        .split_once(' ')
        .map_or((text, None), |(verdict, detail)| (verdict, Some(detail)));
    if detail.is_some_and(str::is_empty) {
        return Err(Error::Value(key));
    }
    Ok(match (verdict, detail.map(ToOwned::to_owned)) {
        ("credited", None) => Ledger::Credited,
        ("unrecorded", None) => Ledger::Unrecorded,
        ("inconclusive", Some(gap)) => Ledger::Inconclusive(gap),
        ("refused", Some(error)) => Ledger::Refused(error),
        ("mismatched", Some(mismatch)) => Ledger::Mismatched(mismatch),
        _ => return Err(Error::Value(key)),
    })
}
